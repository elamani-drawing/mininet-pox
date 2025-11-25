from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.addresses import EthAddr, IPAddr
from pox.openflow.libopenflow_01 import ofp_packet_out, ofp_action_output, OFPP_FLOOD

import time

log = core.getLogger()

class AnalyticalFirewall(object):
    def __init__(self, connection):
        self.connection = connection
        connection.addListeners(self)
        self.modules = []

    def add_module(self, module):
        self.modules.append(module)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet:
            return

        # *** PIPELINE DES FIREWALLS ***
        for module in self.modules:
            consumed = module.handle_packet(event)
            if consumed:
                return  # STOP : module a géré le paquet

        # sinon forwarding minimal
        msg = of.ofp_packet_out(data=event.ofp)
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)


# Parametre flood arp
TEMP_BLOCK_SECONDS = 3600
class ARPFirewall(object):
    def __init__(self, connection):
        self.connection = connection

        self.arp_table = {}     # IP -> (MAC, timestamp)
        self.mac_table = {}     # MAC -> port (learning switch)
        self.blocked = {}             # MAC -> {until, reason}

        log.info("ARPFirewall initialisé pour %s", connection.dpid)

    def now(self):
        return time.time()

    def _handle_PacketIn(self, event):
        packet = event.parsed
        in_port = event.port

        if not packet:
            return

        # ARP detection only
        if packet.type == ethernet.ARP_TYPE:
            self.handle_arp(event, packet, in_port)
            return

        # Learn MAC-port
        self.learn_mac_port(packet.src, in_port)

        # Normal learning-switch behavior
        self.forward_packet(event, packet, in_port)

    
    def handle_packet(self, event):
        self._handle_PacketIn(event)

    def handle_arp(self, event, packet, in_port):
        """Analyse et protection ARP"""
        a = packet.find('arp')
        if not a:
            return

        src_ip = IPAddr(a.protosrc)
        src_mac = EthAddr(a.hwsrc)
        dst_ip = IPAddr(a.protodst)
        now = self.now()
        if self.is_blocked(src_mac):
            log.warning(f"PacketIn ignoré, envoyé par {src_mac}")
            return

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


    def learn_mac_port(self, mac, port):
        """Learning switch : apprend où est chaque MAC"""
        if mac not in self.mac_table or self.mac_table[mac] != port:
            self.mac_table[mac] = port

    def forward_packet(self, event, packet, in_port):
        dst = packet.dst
        msg = of.ofp_packet_out(data=event.ofp)

        if dst.is_multicast:
            msg.actions.append(of.ofp_action_output(port=OFPP_FLOOD))
            self.connection.send(msg)
            return

        if dst in self.mac_table:
            out_port = self.mac_table[dst]
            msg.actions.append(of.ofp_action_output(port=out_port))
        else:
            msg.actions.append(of.ofp_action_output(port=OFPP_FLOOD))

        self.connection.send(msg)

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

# Paramètres et constante DoS
DOS_WINDOW = 5.0         # fenêtre en secondes
DOS_THRESHOLD = 100      # seuil de paquets/window
DOS_BLOCK_TIME = 3600      # temps de blocage d’un host (s)
# Table globale : IP -> (dpid, port, mac)
ip_host_table = {}  # Permet de connaître où bloquer le host

class DOSFirewall(object):
    def __init__(self, connection):
        self.connection = connection
        # Historique de flux pour le comptage DoS
        self.flow_history = {}  # (src_ip, dst_ip) -> timestamps
        # Propriétaire (initiateur) du flux
        self.flow_owner = {}    # (ip1, ip2) -> initiateur
        self.last_reset = time.time()
        log.info("DOSFirewall initialisé pour switch %s", connection.dpid)

    def now(self):
        return time.time()

    # --------------------------------------------------
    #  BLOCAGE D’UN HOST ATTACKER
    # --------------------------------------------------
    def block_host_by_ip(self, src_ip):
        if src_ip not in ip_host_table:
            log.warning("Impossible de bloquer IP %s : inconnu", src_ip)
            return

        dpid, port, mac = ip_host_table[src_ip]

        log.warning("Blocage DoS : installation DROP pour IP %s (MAC %s)", src_ip, mac)

        # Pousser règle DROP sur tous les switches
        for conn in core.openflow._connections.values():
            msg = of.ofp_flow_mod()
            msg.priority = 65535
            msg.match.dl_src = mac
            msg.actions = []        # DROP
            msg.idle_timeout = DOS_BLOCK_TIME
            msg.hard_timeout = DOS_BLOCK_TIME
            conn.send(msg)

        log.warning(">>> HOST %s BLOQUÉ AVEC SUCCÈS <<<", src_ip)

    # --------------------------------------------------
    #  DÉTERMINER L’INITIATEUR DU FLUX
    # --------------------------------------------------
    def get_flow_owner(self, src_ip, dst_ip):
        a = (src_ip, dst_ip)
        b = (dst_ip, src_ip)

        if a not in self.flow_owner and b not in self.flow_owner:
            self.flow_owner[a] = src_ip
            self.flow_owner[b] = src_ip
            return src_ip

        return self.flow_owner.get(a, self.flow_owner.get(b))

    # --------------------------------------------------
    #  DÉTECTION DOS
    # --------------------------------------------------
    def detect_dos(self, src_ip, dst_ip):
        t = self.now()

        # reset périodique
        if t - self.last_reset > DOS_WINDOW:
            self.flow_history.clear()
            self.last_reset = t

        key = (src_ip, dst_ip)
        history = self.flow_history.setdefault(key, [])
        history.append(t)

        # nettoyage
        while history and history[0] < t - DOS_WINDOW:
            history.pop(0)

        if len(history) > DOS_THRESHOLD:
            log.warning("DoS détecté : %s → %s (%d pkts/s)",
                        src_ip, dst_ip, len(history))
            return True

        return False

    def handle_packet(self, event):
        self._handle_PacketIn(event)

    # --------------------------------------------------
    #  PACKET-IN (traitement minimal requis)
    # --------------------------------------------------
    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet:
            return

        in_port = event.port
        src_mac = packet.src

        # Extraire IP
        ip_packet = packet.find('ipv4')
        if not ip_packet:
            return  # On ignore non-IP pour DoS

        src_ip = str(ip_packet.srcip)
        dst_ip = str(ip_packet.dstip)

        # apprendre où se trouve le host
        if src_ip not in ip_host_table:
            ip_host_table[src_ip] = (event.connection.dpid, in_port, src_mac)
            log.info("Host appris : IP %s → switch %s port %s",
                     src_ip, event.connection.dpid, in_port)

        # Détection DoS uniquement par initiateur réel
        owner = self.get_flow_owner(src_ip, dst_ip)
        if owner == src_ip:
            if self.detect_dos(src_ip, dst_ip):
                self.block_host_by_ip(src_ip)
                return

        # Pas de forwarding évolué : simple flood minimal
        msg = of.ofp_packet_out(data=event.ofp)
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)

def launch(**kwargs):
    def start_switch(event):
        fw = AnalyticalFirewall(event.connection)

        # Création de l'état partagé et ajout des modules
        fw.add_module(ARPFirewall(event.connection))
        fw.add_module(DOSFirewall(event.connection))

        log.info("AnalyticalFirewall prêt pour switch %s", event.connection.dpid)

    core.openflow.addListenerByName("ConnectionUp", start_switch)
    log.info("AnalyticalFirewall global activé avec modules ARP et DoS")