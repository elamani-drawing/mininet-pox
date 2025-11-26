from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp
from pox.lib.packet.udp import udp

from ml.utils import (
    now, create_state, get_global_state,
    compute_features, save_to_csv,
    EMIT_INTERVAL, WINDOW_SECONDS, reset_state
)

log = core.getLogger()
state = get_global_state()


def _handle_PacketIn(event):
    packet = event.parsed
    if not packet:
        return

    t = now()
    eth = packet
    src_mac = eth.src

    # ---------------------
    # ARP packets
    # ---------------------
    if eth.type == ethernet.ARP_TYPE:
        a = packet.find('arp')
        if not a:
            return

        src_ip = a.protosrc.toStr()
        s = state[src_ip]

        if s["last_mac"] and s["last_mac"] != src_mac:
            s["mac_changes"] += 1
        s["last_mac"] = src_mac

        if a.opcode == arp.REQUEST:
            s["arp_req"] += 1
        elif a.opcode == arp.REPLY:
            s["arp_rep"] += 1

        s["pkt_times"].append(t)
        s["pkt_count"] += 1
        s["byte_count"] += len(eth)
        s["pkt_sizes"].append(len(eth))

        while s["pkt_times"] and (t - s["pkt_times"][0] > WINDOW_SECONDS):
            s["pkt_times"].popleft()

        return

    # ---------------------
    # IPv4 packets
    # ---------------------
    ip_pkt = packet.find('ipv4')
    if ip_pkt:
        src_ip = ip_pkt.srcip.toStr()
        dst_ip = ip_pkt.dstip.toStr()
        s = state[src_ip]

        if s["last_mac"] and s["last_mac"] != src_mac:
            s["mac_changes"] += 1
        s["last_mac"] = src_mac

        s["pkt_times"].append(t)
        s["pkt_count"] += 1
        s["byte_count"] += len(eth)
        s["pkt_sizes"].append(len(eth))
        s["dst_ips"].add(dst_ip)

        # TTL
        try:
            s["ttls"].append(ip_pkt.ttl)
        except:
            pass

        # ---------------------
        # TCP
        # ---------------------
        tcp_pkt = packet.find('tcp')
        if tcp_pkt:
            s["tcp_count"] += 1
            s["dst_ports"].add(tcp_pkt.dstport)
            s["flows"] += 1

            # Flags
            if tcp_pkt.SYN and not tcp_pkt.ACK:
                s["syn_count"] += 1
                s["incomplete_flows"] += 1
            if tcp_pkt.ACK:
                s["ack_count"] += 1
            if tcp_pkt.FIN:
                s["fin_count"] += 1
            if tcp_pkt.RST:
                s["rst_count"] += 1

        # ---------------------
        # UDP
        # ---------------------
        udp_pkt = packet.find('udp')
        if udp_pkt:
            s["udp_count"] += 1
            s["dst_ports"].add(udp_pkt.dstport)
            s["flows"] += 1

        while s["pkt_times"] and (t - s["pkt_times"][0] > WINDOW_SECONDS):
            s["pkt_times"].popleft()


def _periodic_emit():
    for src_ip, s in list(state.items()):
        if s["pkt_count"] > 0:
            feat = compute_features(src_ip, s)
            save_to_csv(feat)
        reset_state(s)

    core.callDelayed(EMIT_INTERVAL, _periodic_emit)


def launch():
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    core.callDelayed(EMIT_INTERVAL, _periodic_emit)
    log.info("Module POX Collect lancé avec features avancéess.")
