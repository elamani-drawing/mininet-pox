"""
AnalyticalFirewall POX
- ARP : détection de conflits IP-MAC, gratuitous ARP, et blocage immédiat
  des ARP spoofing pour que la table ARP des hôtes légitimes ne soit jamais corrompue.
- Rate limiting : détection des MAC envoyant trop de paquets par seconde.
- Détection DDoS simple : comptage des flux par MAC sur une fenêtre de temps.
- Détection MAC flapping : alerte et blocage temporaire si une MAC change trop de ports.
- Blocage temporaire : installation d'un flow DROP OpenFlow pour les MAC malveillants.
- Comportement learning switch : envoie les paquets vers le port appris ou flood si inconnu.
"""

from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.addresses import EthAddr, IPAddr
from pox.openflow.libopenflow_01 import ofp_packet_out, ofp_action_output, OFPP_FLOOD

import time

log = core.getLogger()

# Paramètres configurables
DDOS_FLOW_THRESHOLD = 30
DDOS_TIME_WINDOW = 10
RATE_LIMIT_PPS = 200
RATE_LIMIT_WINDOW = 1.0
TEMP_BLOCK_SECONDS = 60
MAC_FLAP_THRESHOLD = 3
MAC_FLAP_WINDOW = 60
SHORT_FLOW_TIMEOUT = 2

class AnalyticalFirewall(object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)

        self.arp_table = {}           # IP -> (MAC, timestamp)
        self.flow_timestamps = {}     # MAC -> liste timestamps pour DDoS
        self.packet_timestamps = {}   # MAC -> liste timestamps pour rate-limit
        self.mac_ports = {}           # MAC -> set(ports)
        self.mac_port_changes = {}    # MAC -> liste timestamps de changement
        self.blocked = {}             # MAC -> {until, reason}
        self.mac_table = {}           # MAC -> port (learning switch)

        log.info("AnalyticalFirewall initialisé pour %s", connection)

    def now(self):
        return time.time()

    def is_blocked(self, mac):
        """Retourne True si le MAC est bloqué"""
        info = self.blocked.get(mac)
        if not info:
            return False
        if self.now() > info['until']:
            del self.blocked[mac]
            log.info("Déblocage automatique de %s (raison : %s)", mac, info['reason'])
            return False
        return True

    def block_mac_temporarily(self, mac, seconds=TEMP_BLOCK_SECONDS, reason="inconnu"):
        """Bloque un MAC avec flow DROP OpenFlow"""
        if isinstance(mac, str):
            mac = EthAddr(mac)

        log.warning("Blocage temporaire de %s pour %s secondes (raison : %s)", mac, seconds, reason)
        self.blocked[mac] = {'until': self.now() + seconds, 'reason': reason}

        msg = of.ofp_flow_mod()
        msg.priority = 65535
        msg.actions = []
        msg.match.dl_src = mac
        msg.idle_timeout = seconds
        msg.hard_timeout = seconds
        self.connection.send(msg)
        log.info("Flow DROP installé pour %s", mac)

    def _handle_PacketIn(self, event):
        try:
            packet = event.parsed
        except Exception as e:
            log.warning("Impossible de parser le paquet : %s", e)
            return

        in_port = event.port
        if not packet:
            return

        src_mac = packet.src
        if self.is_blocked(src_mac):
            log.warning(f"PacketIn ignoré, envoyé par {src_mac}")
            return

        if packet.type == ethernet.ARP_TYPE:
            self.handle_arp(event, packet, in_port)
            return

        if packet.type == ethernet.IP_TYPE:
            if self.handle_rate_limit(src_mac):
                return
            self.handle_ddos(src_mac)

        self.learn_mac_port(src_mac, in_port)
        self.handle_learning_switch(event, packet, in_port)

    def handle_arp(self, event, packet, in_port):
        """Analyse et protection ARP"""
        a = packet.find('arp')
        if not a:
            return

        src_ip = IPAddr(a.protosrc)
        src_mac = EthAddr(a.hwsrc)
        dst_ip = IPAddr(a.protodst)
        now = self.now()

        # Protection contre ARP spoofing
        entry = self.arp_table.get(src_ip)
        if entry:
            old_mac, ts = entry
            if old_mac != src_mac:
                log.warning("Conflit ARP détecté : %s - %s (ancien : %s)", src_ip, src_mac, old_mac)
                self.block_mac_temporarily(src_mac, reason="conflit ARP")
                log.info("Paquet ARP usurpé supprimé avant livraison")
                return

        self.arp_table[src_ip] = (src_mac, now)

        if src_ip == dst_ip:
            log.info("ARP gratuitous détecté depuis %s (%s)", src_ip, src_mac)

        # Flood ARP légitime
        msg = of.ofp_packet_out(data=event.ofp)
        msg.actions.append(of.ofp_action_output(port=OFPP_FLOOD))
        self.connection.send(msg)

    def handle_ddos(self, src_mac):
        now = self.now()
        ts_list = [t for t in self.flow_timestamps.get(src_mac, []) if now - t <= DDOS_TIME_WINDOW]
        ts_list.append(now)
        self.flow_timestamps[src_mac] = ts_list

        if len(ts_list) > DDOS_FLOW_THRESHOLD:
            log.warning("Possible attaque DDoS détectée de %s (%d événements)", src_mac, len(ts_list))
            self.block_mac_temporarily(src_mac, reason="ddos")

    def handle_rate_limit(self, src_mac):
        now = self.now()
        pts = [t for t in self.packet_timestamps.get(src_mac, []) if now - t <= RATE_LIMIT_WINDOW]
        pts.append(now)
        self.packet_timestamps[src_mac] = pts

        pps = len(pts) / RATE_LIMIT_WINDOW
        if pps > RATE_LIMIT_PPS:
            log.warning("Rate limit dépassé par %s : %.1f pps", src_mac, pps)
            self.block_mac_temporarily(src_mac, reason="rate-limit")
            return True
        return False

    def learn_mac_port(self, mac, port):
        """Apprentissage MAC-port et détection MAC flapping"""
        now = self.now()
        ports_seen = self.mac_ports.get(mac, set())
        if port not in ports_seen:
            self.mac_port_changes.setdefault(mac, []).append(now)
            changes = [t for t in self.mac_port_changes[mac] if now - t <= MAC_FLAP_WINDOW]
            self.mac_port_changes[mac] = changes
            ports_seen.add(port)
            self.mac_ports[mac] = ports_seen

            if len(changes) >= MAC_FLAP_THRESHOLD:
                log.warning("MAC flapping détecté pour %s (%d changements)", mac, len(changes))
                self.block_mac_temporarily(mac, reason="mac-flap")

        self.mac_table[mac] = port

    def handle_learning_switch(self, event, packet, in_port):
        dst = packet.dst
        msg = of.ofp_packet_out(data=event.ofp)

        if dst.is_multicast:
            msg.actions.append(of.ofp_action_output(port=OFPP_FLOOD))
            self.connection.send(msg)
            return

        if dst in self.mac_table:
            out_port = self.mac_table[dst]
            if out_port != in_port:
                msg.actions.append(of.ofp_action_output(port=out_port))
                self.connection.send(msg)
        else:
            msg.actions.append(of.ofp_action_output(port=OFPP_FLOOD))
            self.connection.send(msg)

def launch(**kwargs):
    def start_switch(event):
        log.debug("Démarrage de l'AnalyticalFirewall pour %s", event.connection)
        AnalyticalFirewall(event.connection)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
    log.info("AnalyticalFirewall chargé et actif")
