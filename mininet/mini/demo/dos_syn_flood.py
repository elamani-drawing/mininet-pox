#!/usr/bin/env python3

"""
dos_syn_flood.py

Usage:
  sudo python3 dos_syn_flood.py --target 10.0.1.10 --port 80 --iface att-eth0

Ce script :
 - démarre la topologie via create_network() (topology.py)
 - lance start_syn_flood(att, target, port, iface)
 - ouvre la CLI Mininet pour observation
 - au exit: stop_syn_flood() et net.stop()
"""
import argparse
from mini.topology import create_network
from mini.demo.utils import start_syn_flood, stop_syn_flood
from mininet.cli import CLI

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', required=True, help="IP de la cible (ex: 10.0.1.10)")
    parser.add_argument('--port', type=int, default=80, help="Port cible (default 80)")
    parser.add_argument('--iface', default='att-eth0', help="Interface d'att (ex: att-eth0)")
    parser.add_argument('--controller', default='pox', help="IP/hostname du contrôleur (par défaut 'pox')")
    args = parser.parse_args()

    net = None
    try:
        net = create_network(controller_ip=args.controller)
        att = net.get('att')

        print(f"[*] Lancement SYN flood : target={args.target}:{args.port} via iface={args.iface}")
        start_syn_flood(att, target_ip=args.target, port=args.port, iface=args.iface)

        # print("\n*** SYN flood en cours. Ouvre la CLI Mininet pour observer (ex: 'srv tcpdump -i srv-eth0 tcp port 80').\n")
        CLI(net)

    except Exception as e:
        print(f"[!] Erreur: {e}")

    finally:
        if net:
            print("[*] Nettoyage : arrêt du SYN flood et arrêt du réseau.")
            try:
                stop_syn_flood(net.get('att'))
            except Exception as e:
                print("[!] Erreur lors du stop_syn_flood:", e)
            net.stop()

if __name__ == '__main__':
    main()
