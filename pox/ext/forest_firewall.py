from pox.core import core
import pox.openflow.libopenflow_01 as of
from pox.lib.packet.ethernet import ethernet
from pox.lib.packet.arp import arp
from pox.lib.packet.ipv4 import ipv4
from pox.lib.packet.tcp import tcp
from pox.lib.packet.udp import udp
import pandas as pd


from ml.utils import (
    now, create_state, get_global_state,
    compute_features, reset_state
)

import joblib
from sklearn.preprocessing import StandardScaler

log = core.getLogger()
state = get_global_state()

# Charger modèle + scaler
DIR_TMP = "/tmp/pox/"
DIR_MODELS = DIR_TMP + "models/"
model = joblib.load(DIR_MODELS + "iforest_model.pkl")
scaler = joblib.load(DIR_MODELS + "scaler.pkl")

EMIT_INTERVAL = 5  # Exemple : toutes les 5

malicious_ips = set()      # IPs détectées comme malveillantes
blocked_pairs = set()      # paires (src_ip, dst_ip) à bloquer


def _handle_PacketIn(event):
    packet = event.parsed
    if not packet:
        return

    t = now()
    eth = packet
    src_mac = eth.src

    # --------------------- ARP ---------------------
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

        while s["pkt_times"] and (t - s["pkt_times"][0] > EMIT_INTERVAL):
            s["pkt_times"].popleft()
        return

    # --------------------- IPv4 ---------------------
    ip_pkt = packet.find('ipv4')
    if ip_pkt:
        src_ip = ip_pkt.srcip.toStr()
        dst_ip = ip_pkt.dstip.toStr()

        if src_ip in malicious_ips and dst_ip in malicious_ips:
            # Si les deux sont malveillantes, drop
            log.warning(f"Drop paquet entre {src_ip} <-> {dst_ip}")
            event.halt = True  # empêche l'envoi du paquet
            blocked_pairs.add((src_ip, dst_ip))
            return

        s = state[src_ip]

        if s["last_mac"] and s["last_mac"] != src_mac:
            s["mac_changes"] += 1
        s["last_mac"] = src_mac

        s["pkt_times"].append(t)
        s["pkt_count"] += 1
        s["byte_count"] += len(eth)
        s["pkt_sizes"].append(len(eth))
        s["dst_ips"].add(dst_ip)

        try:
            s["ttls"].append(ip_pkt.ttl)
        except:
            pass

        tcp_pkt = packet.find('tcp')
        if tcp_pkt:
            s["tcp_count"] += 1
            s["dst_ports"].add(tcp_pkt.dstport)
            s["flows"] += 1

            if tcp_pkt.SYN and not tcp_pkt.ACK:
                s["syn_count"] += 1
                s["incomplete_flows"] += 1
            if tcp_pkt.ACK:
                s["ack_count"] += 1
            if tcp_pkt.FIN:
                s["fin_count"] += 1
            if tcp_pkt.RST:
                s["rst_count"] += 1

        udp_pkt = packet.find('udp')
        if udp_pkt:
            s["udp_count"] += 1
            s["dst_ports"].add(udp_pkt.dstport)
            s["flows"] += 1

        while s["pkt_times"] and (t - s["pkt_times"][0] > EMIT_INTERVAL):
            s["pkt_times"].popleft()


def _periodic_firewall():
    if len(state.items()) == 0 :
        log.info("Pas de donnée")
        return 
    for src_ip, s in list(state.items()):
        if s["pkt_count"] == 0:
            continue  # rien à analyser

        feat = compute_features(src_ip, s)
        try:
            feat_df = pd.DataFrame([feat])
            numeric_cols = [c for c in feat_df.columns if c not in ["timestamp", "src_ip"]]
            X_scaled = scaler.transform(feat_df[numeric_cols])
            pred = model.predict(X_scaled)[0]
        except Exception as e:
            log.error(f"Erreur ML pour {src_ip}: {e}")
            pred = 1  # on considère normal par défaut

        if pred == -1:
            log.warning(f"Anomalie détectée sur {src_ip} - blocage du trafic")
            malicious_ips.add(src_ip) 
            _block_ip(src_ip)
        else: 
            log.info("Aucun probleme detecter")

        reset_state(s)

    core.callDelayed(EMIT_INTERVAL, _periodic_firewall)


def _block_ip(ip):
    # pass
    for conn in core.openflow._connections.values():
        fm = of.ofp_flow_mod()
        fm.match.dl_type = 0x800  # IPv4
        fm.match.nw_src = ip
        fm.actions = []  # pas d'action = drop
        fm.priority = 100
        conn.send(fm)
        log.info(f"Flow ajouté pour bloquer {ip}")


def launch():
    core.openflow.addListenerByName("PacketIn", _handle_PacketIn)
    core.callDelayed(EMIT_INTERVAL, _periodic_firewall)
    log.info("Module POX Firewall ML lancé.")
