import csv
import os
import time
import joblib
from collections import defaultdict, deque
import math

WINDOW_SECONDS = 10.0
EMIT_INTERVAL = 1.0

FEATURES_CSV = "/tmp/pox/pox_features.csv"
MODEL_PATH = "/tmp/pox/iforest_model.pkl"
SCALER_PATH = "/tmp/pox/scaler.pkl"


def now():
    return time.time()


def create_state():
    """Retourne la structure de state pour un nouvel host."""
    return {
        "pkt_times": deque(),
        "pkt_count": 0,
        "byte_count": 0,
        "dst_ips": set(),
        "dst_ports": set(),
        "syn_count": 0,
        "tcp_count": 0,
        "arp_req": 0,
        "arp_rep": 0,
        "last_mac": None,
        "mac_changes": 0,
    }

def get_global_state():
    return defaultdict(create_state)


def compute_features(src_ip, s):
    pkt_count = s["pkt_count"]
    byte_count = s["byte_count"]
    duration = WINDOW_SECONDS if pkt_count > 0 else 1
    pkts_per_sec = pkt_count / duration
    bytes_per_sec = byte_count / duration
    unique_dst_ips = len(s["dst_ips"])
    unique_dst_ports = len(s["dst_ports"])
    avg_pkt_size = (byte_count / pkt_count) if pkt_count > 0 else 0

    times = list(s["pkt_times"])
    ias = [t2 - t1 for t1, t2 in zip(times, times[1:])]
    std_ias = (sum((x - (sum(ias)/len(ias)))**2 for x in ias)/len(ias))**0.5 if len(ias) > 1 else 0

    syn_ratio = (s["syn_count"] / s["tcp_count"]) if s["tcp_count"] > 0 else 0

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
        "std_ias": std_ias,
        "syn_count": s["syn_count"],
        "syn_ratio": syn_ratio,
        "arp_req": s["arp_req"],
        "arp_rep": s["arp_rep"],
        "mac_changes": s["mac_changes"]
    }

FEATURE_HEADER = [
    "timestamp","src_ip","pkt_count","byte_count","pkts_per_sec","bytes_per_sec",
    "unique_dst_ips","unique_dst_ports","avg_pkt_size","std_ias","syn_count",
    "syn_ratio","arp_req","arp_rep","mac_changes"
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
    s["pkt_count"] = 0
    s["byte_count"] = 0
    s["dst_ips"].clear()
    s["dst_ports"].clear()
    s["syn_count"] = 0
    s["tcp_count"] = 0
    s["arp_req"] = 0
    s["arp_rep"] = 0
    s["mac_changes"] = 0
    s["pkt_times"].clear()
