#!/usr/bin/env python3

"""
dos_http_flood.py

Usage:
  sudo python3 dos_http_flood.py --target 10.0.1.10 --port 80 --threads 20 --reqs 1000

Ce script :
 - démarre la topologie via create_network() (topology.py)
 - lance start_http_flood(att, target, port, threads, reqs)
 - ouvre la CLI Mininet pour observation
 - au exit: stop_http_flood() et net.stop()
"""
import argparse
from mini.topology import create_network
from mini.demo.utils import start_http_flood, stop_http_flood  
from mininet.cli import CLI

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--target', required=True, help="IP de la cible (ex: 10.0.1.10)")
    parser.add_argument('--port', type=int, default=80, help="Port HTTP cible (default 80)")
    parser.add_argument('--threads', type=int, default=10, help="Nombre de threads (default 10)")
    parser.add_argument('--reqs', type=int, default=1000, help="Requests par thread (default 1000)")
    parser.add_argument('--controller', default='pox', help="IP/hostname du contrôleur (par défaut 'pox')")
    args = parser.parse_args()

    net = None
    try:
        net = create_network(controller_ip=args.controller)
        att = net.get('att')

        print(f"[*] Lancement HTTP flood : target={args.target}:{args.port} threads={args.threads} reqs={args.reqs}")
        start_http_flood(att, target_ip=args.target, port=args.port, threads=args.threads, reqs=args.reqs)

        # print("\n*** HTTP flood en cours. Ouvre la CLI Mininet pour observer (ex: 'srv tcpdump -i srv-eth0 tcp port 80').\n")
        CLI(net)

    except Exception as e:
        print(f"[!] Erreur: {e}")

    finally:
        if net:
            print("[*] Nettoyage : arrêt du HTTP flood et arrêt du réseau.")
            try:
                stop_http_flood(net.get('att'))
            except Exception as e:
                print("[!] Erreur lors du stop_http_flood:", e)
            net.stop()

if __name__ == '__main__':
    main()
