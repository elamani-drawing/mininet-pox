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
        # Normal learning-switch behavior
        self.forward_packet(event)

    def forward_packet(self, event): 
        # log.info("forwarding par analytical")
        msg = of.ofp_packet_out(data=event.ofp)
        msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        self.connection.send(msg)


# Paramètre : durée de blocage temporaire en cas de flood ou spoof ARP
SPOOF_ARP_BLOCK_SECONDS = 3600

class ARPFirewall(object):
    """
    Firewall ARP basique pour POX.
    Fonctions :
      - Apprendre les correspondances MAC ↔ port (learning switch)
      - Construire une table ARP pour détecter les incohérences
      - Bloquer temporairement les MAC suspects (ARP spoofing, conflit ARP)
      - Gérer et filtrer les paquets ARP
    """

    def __init__(self, connection):
        """
        Initialise les tables internes pour un switch donné.
        """
        self.connection = connection

        self.arp_table = {}      # Associe une IP à (MAC, timestamp)
        self.mac_table = {}      # Associe une MAC à un port (switch learning)
        self.blocked = {}        # MAC -> infos de blocage (expiration, raison)

        log.info("ARPFirewall initialisé pour %s", connection.dpid)

    def now(self):
        """Renvoie le timestamp actuel."""
        return time.time()

    def _handle_PacketIn(self, event):
        """
        Traite tous les paquets reçus.
        Ne s’intéresse vraiment qu’aux paquets ARP.
        """
        packet = event.parsed
        in_port = event.port

        if not packet:
            return

        # Traitement des paquets ARP uniquement
        if packet.type == ethernet.ARP_TYPE:
            self.handle_arp(event, packet, in_port)
            return

        # Pour les autres paquets : apprentissage MAC → port
        self.learn_mac_port(packet.src, in_port)

        # C'est la classe appellante qui gere le forwarding
        # Flood minimal en absence de forwarding avancé
        # msg = of.ofp_packet_out(data=event.ofp)
        # msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        # self.connection.send(msg)

    def handle_packet(self, event):
        """Wrapper simple pour le handler PacketIn."""
        self._handle_PacketIn(event)

    def handle_arp(self, event, packet, in_port):
        """
        Analyse le paquet ARP et applique les protections :
          - Détection de conflits ARP
          - Blocage des MAC suspectes
          - Mise à jour de la table ARP
          - Diffusion (flood) du paquet s'il est légitime
        """
        a = packet.find('arp')
        if not a:
            return

        src_ip = IPAddr(a.protosrc)
        src_mac = EthAddr(a.hwsrc)
        dst_ip = IPAddr(a.protodst)
        now = self.now()

        # Vérifie si la source est actuellement bloquée
        if self.is_blocked(src_mac):
            log.warning(f"Paquet ARP ignoré (MAC bloquée) : {src_mac}")
            return

        # Détection d’un conflit ARP : même IP mais MAC différente
        entry = self.arp_table.get(src_ip)
        if entry:
            old_mac, ts = entry
            if old_mac != src_mac:
                log.warning("Conflit ARP détecté : %s utilisé par %s (ancien : %s)",
                            src_ip, src_mac, old_mac)

                self.block_mac_temporarily(src_mac, reason="conflit ARP")
                log.info("Paquet ARP suspect supprimé")
                return

        # Mise à jour de la table ARP
        self.arp_table[src_ip] = (src_mac, now)

        # Détection d’un ARP gratuitous
        if src_ip == dst_ip:
            log.info("ARP gratuitous depuis %s (%s)", src_ip, src_mac)

        # Flood du paquet ARP (comportement normal)
        msg = of.ofp_packet_out(data=event.ofp)
        msg.actions.append(of.ofp_action_output(port=OFPP_FLOOD))
        self.connection.send(msg)

    def learn_mac_port(self, mac, port):
        """
        Learning switch : associe une adresse MAC au port où elle a été vue.
        """
        if mac not in self.mac_table or self.mac_table[mac] != port:
            self.mac_table[mac] = port

    def block_mac_temporarily(self, mac, seconds=SPOOF_ARP_BLOCK_SECONDS, reason="inconnu"):
        """
        Bloque temporairement une adresse MAC via un flow DROP.
        Empêche tout trafic provenant de cette MAC pendant la durée indiquée.
        """
        if isinstance(mac, str):
            mac = EthAddr(mac)

        log.warning("Blocage de %s pour %s secondes (raison : %s)",
                    mac, seconds, reason)

        self.blocked[mac] = {
            'until': self.now() + seconds,
            'reason': reason
        }

        # Installation du flow DROP
        msg = of.ofp_flow_mod()
        msg.priority = 65535
        msg.actions = []  # Aucune action → DROP
        msg.match.dl_src = mac
        msg.idle_timeout = seconds
        msg.hard_timeout = seconds
        self.connection.send(msg)

        log.info("Flow DROP installé pour %s", mac)

    def is_blocked(self, mac):
        """
        Indique si une MAC est actuellement bloquée.
        Suppression automatique si le blocage est expiré.
        """
        info = self.blocked.get(mac)
        if not info:
            return False

        if self.now() > info['until']:
            del self.blocked[mac]
            log.info("Déblocage automatique de %s (raison initiale : %s)",
                     mac, info['reason'])
            return False

        return True
   
# Paramètres de détection DoS
DOS_WINDOW = 5.0          # Fenêtre d'observation en secondes
DOS_THRESHOLD = 100       # Seuil de paquets par fenêtre
DOS_BLOCK_TIME = 3600     # Durée de blocage d’un host en secondes

# Table globale : permet de retrouver sur quel switch/port/MAC se trouve une IP
ip_host_table = {}        # IP -> (dpid, port, mac)

class DOSFirewall(object):
    """
    Firewall DoS pour POX.
    Fonctions :
      - Suivi du nombre de paquets échangés entre IPs
      - Détection d'activité DoS (trop de paquets par fenêtre)
      - Identification de l’initiateur du flux
      - Blocage global d’un host sur tous les switches
    """

    def __init__(self, connection):
        """
        Initialise l'état du firewall pour un switch donné.
        """
        self.connection = connection

        # Historique des flux : associe un couple IP→IP à une liste de timestamps
        self.flow_history = {}

        # Mémorise qui a initié un flux (utile pour éviter de pénaliser la victime)
        self.flow_owner = {}

        self.last_reset = time.time()

        log.info("DOSFirewall initialisé pour switch %s", connection.dpid)

    def now(self):
        """Renvoie le timestamp actuel."""
        return time.time()


    def block_host_by_ip(self, src_ip):
        """
        Bloque un host sur tous les switches en installant un flow DROP
        basé sur son adresse MAC.
        """
        if src_ip not in ip_host_table:
            log.warning("Impossible de bloquer IP %s : inconnue", src_ip)
            return

        dpid, port, mac = ip_host_table[src_ip]

        log.warning("Blocage DoS : installation DROP pour IP %s (MAC %s)", src_ip, mac)

        # Installation de la règle DROP sur tous les switches
        for conn in core.openflow._connections.values():
            msg = of.ofp_flow_mod()
            msg.priority = 65535
            msg.match.dl_src = mac
            msg.actions = []                 # Aucune action → DROP
            msg.idle_timeout = DOS_BLOCK_TIME
            msg.hard_timeout = DOS_BLOCK_TIME
            conn.send(msg)

        log.warning(">>> HOST %s BLOQUÉ AVEC SUCCÈS <<<", src_ip)

    def get_flow_owner(self, src_ip, dst_ip):
        """
        Identifie l’initiateur réel d’un flux IP↔IP.
        Le premier qui émet un paquet est considéré comme propriétaire.
        """
        a = (src_ip, dst_ip)
        b = (dst_ip, src_ip)

        # Premier paquet pour ce couple → src_ip devient l’initiateur
        if a not in self.flow_owner and b not in self.flow_owner:
            self.flow_owner[a] = src_ip
            self.flow_owner[b] = src_ip
            return src_ip

        # Retourne l’initiateur enregistré
        return self.flow_owner.get(a, self.flow_owner.get(b))

    def detect_dos(self, src_ip, dst_ip):
        """
        Compte le nombre de paquets pour un couple IP→IP
        dans une fenêtre glissante et déclenche une alerte
        s'il dépasse le seuil configuré.
        """
        t = self.now()

        # Réinitialisation périodique de l'historique
        if t - self.last_reset > DOS_WINDOW:
            self.flow_history.clear()
            self.last_reset = t

        key = (src_ip, dst_ip)
        history = self.flow_history.setdefault(key, [])
        history.append(t)

        # Suppression des timestamps trop anciens
        while history and history[0] < t - DOS_WINDOW:
            history.pop(0)

        # Détection d’un volume anormal
        if len(history) > DOS_THRESHOLD:
            log.warning("DoS détecté : %s → %s (%d pkts/s)",
                        src_ip, dst_ip, len(history))
            return True

        return False

    def handle_packet(self, event):
        """Handler principal appelé par POX."""
        self._handle_PacketIn(event)

    def _handle_PacketIn(self, event):
        """
        Analyse minimale des paquets :
          - Extraction IP
          - Apprentissage de la position du host
          - Détection DoS si l’émetteur est l’initiateur du flux
          - Flood basique des paquets
        """
        packet = event.parsed
        if not packet:
            return

        in_port = event.port
        src_mac = packet.src

        # Extraction IPv4 uniquement
        ip_packet = packet.find('ipv4')
        if not ip_packet:
            return

        src_ip = str(ip_packet.srcip)
        dst_ip = str(ip_packet.dstip)

        # Enregistre où se trouve le host (switch, port, MAC)
        if src_ip not in ip_host_table:
            ip_host_table[src_ip] = (event.connection.dpid, in_port, src_mac)
            log.info("Host appris : IP %s → switch %s port %s",
                     src_ip, event.connection.dpid, in_port)

        # Détection DoS seulement pour l’initiateur du flux
        owner = self.get_flow_owner(src_ip, dst_ip)
        if owner == src_ip:
            if self.detect_dos(src_ip, dst_ip):
                self.block_host_by_ip(src_ip)
                return

        # C'est la classe appellante qui gere le forwarding
        # Flood minimal en absence de forwarding avancé
        # msg = of.ofp_packet_out(data=event.ofp)
        # msg.actions.append(of.ofp_action_output(port=of.OFPP_FLOOD))
        # self.connection.send(msg)
   

def launch(**kwargs):
    """
    Initialise le firewall global.
    À chaque nouveau switch connecté, un AnalyticalFirewall est créé
    et on lui ajoute les modules ARP et DoS.
    """

    def start_switch(event):
        """
        Appelé lorsqu'un nouveau switch se connecte.
        Initialise le firewall du switch et y ajoute les modules actifs.
        """
        fw = AnalyticalFirewall(event.connection)

        # Ajout des modules de sécurité
        fw.add_module(ARPFirewall(event.connection))   # Protection ARP
        fw.add_module(DOSFirewall(event.connection))   # Détection/Blocage DoS

        log.info("AnalyticalFirewall prêt pour switch %s", event.connection.dpid)

    # Appelle start_switch à chaque nouvelle connexion OpenFlow
    core.openflow.addListenerByName("ConnectionUp", start_switch)
    log.info("AnalyticalFirewall global activé avec modules ARP et DoS")
