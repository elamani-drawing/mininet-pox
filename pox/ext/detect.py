from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp

log = core.getLogger()

def _handle_PacketIn(event):
    packet = event.parsed
    if not packet:
        return
    # Si paquet ARP
    if packet.type == ethernet.ARP_TYPE:
        a = packet.payload
        # log ARP requests/replies
        if a.opcode == arp.REQUEST:
            log.info("ARP REQUEST: %s => %s (from %s)" % (a.protosrc, a.protodst, packet.src))
        elif a.opcode == arp.REPLY:
            log.info("ARP REPLY: %s is-at %s" % (a.protosrc, a.hwsrc))
    
    ipv4_pkt = packet.find('ipv4')
    if ipv4_pkt:
        log.info("IP PACKET: %s -> %s (proto=%s)" %
                 (ipv4_pkt.srcip, ipv4_pkt.dstip, ipv4_pkt.protocol))
        
def launch():
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    log.info("detect module lancé")
