import csv
import os
import time
import joblib
from collections import defaultdict, deque
import math

WINDOW_SECONDS = 5.0
EMIT_INTERVAL = 1.0

DIR_TMP = "/tmp/pox/"
DIR_FEATURES = DIR_TMP+ "features/"
DIR_MODELS = DIR_TMP+ "models/"

FEATURES_CSV = DIR_TMP+"pox_features.csv"
MODEL_PATH = DIR_MODELS+"iforest_model.pkl"
SCALER_PATH = DIR_MODELS+"scaler.pkl"


def now():
    return time.time()


def create_state():
    """State pour chaque src_ip."""
    return {
        "pkt_times": deque(),
        "pkt_sizes": deque(),
        "pkt_count": 0,
        "byte_count": 0,

        "dst_ips": set(),
        "dst_ports": set(),

        # flows & TCP flags
        "tcp_count": 0,
        "udp_count": 0,
        "syn_count": 0,
        "ack_count": 0,
        "fin_count": 0,
        "rst_count": 0,
        "flows": 0,
        "incomplete_flows": 0,

        # TTL samples
        "ttls": [],

        # ARP / MAC
        "arp_req": 0,
        "arp_rep": 0,
        "last_mac": None,
        "mac_changes": 0,
    }


def get_global_state():
    return defaultdict(create_state)


def compute_entropy(values):
    """Entropie simple."""
    if not values:
        return 0
    total = len(values)
    counts = {}
    for v in values:
        counts[v] = counts.get(v, 0) + 1
    return -sum((c/total) * math.log((c/total), 2) for c in counts.values())


def compute_features(src_ip, s):
    pkt_count = s["pkt_count"]
    byte_count = s["byte_count"]
    duration = WINDOW_SECONDS if pkt_count > 0 else 1

    pkts_per_sec = pkt_count / duration
    bytes_per_sec = byte_count / duration

    unique_dst_ips = len(s["dst_ips"])
    unique_dst_ports = len(s["dst_ports"])

    avg_pkt_size = byte_count / pkt_count if pkt_count > 0 else 0
    std_pkt_size = (sum((x - avg_pkt_size)**2 for x in s["pkt_sizes"]) / len(s["pkt_sizes"]))**0.5 if len(s["pkt_sizes"]) > 1 else 0

    # Inter-arrival times
    times = list(s["pkt_times"])
    ias = [t2 - t1 for t1, t2 in zip(times, times[1:])]
    if len(ias) > 1:
        mean_ias = sum(ias) / len(ias)
        std_ias = (sum((x - mean_ias)**2 for x in ias) / len(ias))**0.5
        burstiness = std_ias / mean_ias if mean_ias > 0 else 0
    else:
        std_ias = 0
        burstiness = 0

    syn_ratio = s["syn_count"] / s["tcp_count"] if s["tcp_count"] > 0 else 0
    incomplete_flow_ratio = s["incomplete_flows"] / s["flows"] if s["flows"] > 0 else 0

    # TTL stats
    ttl_mean = sum(s["ttls"]) / len(s["ttls"]) if s["ttls"] else 0
    ttl_std = (sum((v - ttl_mean)**2 for v in s["ttls"]) / len(s["ttls"]))**0.5 if len(s["ttls"]) > 1 else 0

    # Entropies
    entropy_dst_ports = compute_entropy(list(s["dst_ports"]))

    return {
        "timestamp": now(),
        "src_ip": src_ip,

        "pkt_count": pkt_count,
        "byte_count": byte_count,
        "pkts_per_sec": pkts_per_sec,
        "bytes_per_sec": bytes_per_sec,
        "unique_dst_ips": unique_dst_ips,
        "unique_dst_ports": unique_dst_ports,
        "avg_pkt_size": avg_pkt_size,
        "std_pkt_size": std_pkt_size,
        "std_ias": std_ias,
        "burstiness": burstiness,

        # TCP + flows
        "tcp_count": s["tcp_count"],
        "udp_count": s["udp_count"],
        "syn_count": s["syn_count"],
        "ack_count": s["ack_count"],
        "fin_count": s["fin_count"],
        "rst_count": s["rst_count"],
        "syn_ratio": syn_ratio,
        "flows": s["flows"],
        "incomplete_flow_ratio": incomplete_flow_ratio,

        # TTL
        "ttl_mean": ttl_mean,
        "ttl_std": ttl_std,

        # Entropies
        "entropy_dst_ports": entropy_dst_ports,

        # ARP / spoofing
        "arp_req": s["arp_req"],
        "arp_rep": s["arp_rep"],
        "mac_changes": s["mac_changes"],
    }


FEATURE_HEADER = [
    "timestamp","src_ip","pkt_count","byte_count","pkts_per_sec","bytes_per_sec",
    "unique_dst_ips","unique_dst_ports","avg_pkt_size","std_pkt_size","std_ias","burstiness",
    "tcp_count","udp_count","syn_count","ack_count","fin_count","rst_count","syn_ratio",
    "flows","incomplete_flow_ratio","ttl_mean","ttl_std","entropy_dst_ports",
    "arp_req","arp_rep","mac_changes"
]


def save_to_csv(features, file_path=FEATURES_CSV):
    file_exists = os.path.exists(file_path)
    with open(file_path, "a", newline="") as f:
        writer = csv.writer(f)
        if not file_exists:
            writer.writerow(FEATURE_HEADER)
        writer.writerow([features[k] for k in FEATURE_HEADER])


def load_model():
    model = joblib.load(MODEL_PATH)
    scaler = joblib.load(SCALER_PATH)
    return model, scaler


def reset_state(s):
    s["pkt_times"].clear()
    s["pkt_sizes"].clear()
    s["pkt_count"] = 0
    s["byte_count"] = 0
    s["dst_ips"].clear()
    s["dst_ports"].clear()

    s["tcp_count"] = 0
    s["udp_count"] = 0
    s["syn_count"] = 0
    s["ack_count"] = 0
    s["fin_count"] = 0
    s["rst_count"] = 0

    s["flows"] = 0
    s["incomplete_flows"] = 0
    s["ttls"].clear()

    s["arp_req"] = 0
    s["arp_rep"] = 0
    s["mac_changes"] = 0
