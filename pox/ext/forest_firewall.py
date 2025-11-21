from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp
from pox.lib.packet.udp import udp

from ml.utils import (
    now, create_state, get_global_state,
    compute_features, load_model,
    EMIT_INTERVAL, WINDOW_SECONDS, reset_state
)

import numpy as np

log = core.getLogger()
state = get_global_state()

model = None
scaler = None

def _load_model_once():
    global model, scaler
    if model is None:
        model, scaler = load_model()
        log.info("Isolation Forest + scaler chargés.")

def classify(src_ip, s):
    """Retourne True si anomalie (attaque), False sinon"""
    feat = compute_features(src_ip, s)

    # vecteur ordonné
    X = np.array([[
        feat["pkt_count"], feat["byte_count"], feat["pkts_per_sec"],
        feat["bytes_per_sec"], feat["unique_dst_ips"], feat["unique_dst_ports"],
        feat["avg_pkt_size"], feat["std_ias"], feat["syn_count"], feat["syn_ratio"],
        feat["arp_req"], feat["arp_rep"], feat["mac_changes"]
    ]])

    X_scaled = scaler.transform(X)
    pred = model.predict(X_scaled)[0]  # -1 = anomalie

    return pred == -1, feat

def _handle_PacketIn(event):
    _load_model_once()

    packet = event.parsed
    if not packet:
        return

    t = now()
    eth = packet
    src_mac = eth.src

    # ARP
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

    # IPv4
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
        s["dst_ips"].add(dst_ip)

        tcp_pkt = packet.find('tcp')
        if tcp_pkt:
            s["tcp_count"] += 1
            s["dst_ports"].add(tcp_pkt.dstport)
            if tcp_pkt.SYN and not tcp_pkt.ACK:
                s["syn_count"] += 1

        udp_pkt = packet.find('udp')
        if udp_pkt:
            s["dst_ports"].add(udp_pkt.dstport)

        while s["pkt_times"] and (t - s["pkt_times"][0] > WINDOW_SECONDS):
            s["pkt_times"].popleft()

def _periodic_check():
    _load_model_once()

    for src_ip, s in list(state.items()):
        if s["pkt_count"] == 0:
            continue

        attack, feat = classify(src_ip, s)

        if attack:
            log.error(f"⚠️  Attaque détectée depuis {src_ip}: {feat}")

    core.callDelayed(EMIT_INTERVAL, _periodic_check)

def launch():
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    core.callDelayed(EMIT_INTERVAL, _periodic_check)
    log.info("Module POX Forest-Firewall lancé.")
