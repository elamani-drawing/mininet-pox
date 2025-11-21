from pox.core import core
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.addresses import EthAddr, IPAddr
from pox.openflow.libopenflow_01 import ofp_action_output, ofp_flow_mod, ofp_packet_out
from pox.lib.revent import EventMixin

log = core.getLogger()

class ProxyRouter(EventMixin):
    def __init__(self):
        self.arp_table = {}   # IP -> MAC
        self.ip_port   = {}   # IP -> port
        self.listenTo(core.openflow)
        log.info("ProxyRouter chargé")

    def _handle_ConnectionUp(self, event):
        log.info("Switch %s connecté" % event.dpid)

    def _handle_PacketIn(self, event):
        packet = event.parsed
        if not packet.parsed: return

        inport = event.port

        # ---- ARP ----
        if packet.type == ethernet.ARP_TYPE:
            a = packet.payload

            # Apprentissage IP/MAC/port
            self.arp_table[str(a.protosrc)] = str(a.hwsrc)
            self.ip_port[str(a.protosrc)]   = inport

            # Bloquer ARP reply venant des hôtes
            if a.opcode == arp.REPLY:
                return

            # ARP Request = Proxy ARP
            if a.opcode == arp.REQUEST:
                dst_ip = str(a.protodst)
                if dst_ip in self.arp_table:
                    self.send_arp_reply(event, a)
                else:
                    # Flood pour découvrir
                    msg = ofp_packet_out()
                    msg.data = event.ofp
                    msg.actions.append(ofp_action_output(port=0xfffb))
                    event.connection.send(msg)
                return

        # ---- IP ----
        if packet.type == ethernet.IP_TYPE:
            ip = packet.payload
            dst_ip = str(ip.dstip)

            # Connaît route ?
            if dst_ip in self.ip_port:
                outport = self.ip_port[dst_ip]

                # Installer flow
                fm = ofp_flow_mod()
                fm.match.dl_type = 0x0800
                fm.match.nw_dst = IPAddr(dst_ip)
                fm.actions.append(ofp_action_output(port=outport))
                event.connection.send(fm)

                # Forward paquet
                po = ofp_packet_out()
                po.data = event.ofp
                po.actions.append(ofp_action_output(port=outport))
                event.connection.send(po)
                return

            # Sinon flood
            po = ofp_packet_out()
            po.data = event.ofp
            po.actions.append(ofp_action_output(port=0xfffb))
            event.connection.send(po)
            return

    def send_arp_reply(self, event, req):
        # Construire ARP reply
        r = arp()
        r.opcode = arp.REPLY
        r.hwsrc = EthAddr(self.arp_table[str(req.protodst)])
        r.hwdst = req.hwsrc
        r.protosrc = req.protodst
        r.protodst = req.protosrc

        e = ethernet(type=ethernet.ARP_TYPE,
                     src=r.hwsrc,
                     dst=r.hwdst)
        e.payload = r

        po = ofp_packet_out()
        po.data = e.pack()
        po.actions.append(ofp_action_output(port=event.port))
        event.connection.send(po)


def launch():
    core.registerNew(ProxyRouter)
