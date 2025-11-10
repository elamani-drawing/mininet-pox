#!/usr/bin/env python3
"""
arp_spoof.py

Usage:
  sudo python3 arp_spoof.py --targets 10.0.2.10,10.0.2.11 --spoof 10.0.2.1 --iface att-eth0

Ce script :
 - démarre la topologie via create_network() (topology.py)
 - lance start_arp_spoof(att, targets_csv, spoof_ip, iface)
 - ouvre la CLI Mininet pour observation
 - au exit: stop_arp_spoof() et net.stop()
"""
import argparse
from mini.topology import create_network
from mini.demo.utils import start_arp_spoof, stop_arp_spoof 
from mininet.cli import CLI

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--targets', required=True,
                        help="Liste CSV des IP cibles (ex: 10.0.2.10,10.0.2.11)")
    parser.add_argument('--spoof', required=True, help="IP à usurper (ex: 10.0.2.1)")
    parser.add_argument('--iface', default='att-eth0', help="Interface d'att (ex: att-eth0)")
    parser.add_argument('--controller', default='pox', help="IP/hostname du contrôleur (par défaut 'pox')")
    args = parser.parse_args()

    net = None
    try:
        # Démarrer la topologie
        net = create_network(controller_ip=args.controller)
        att = net.get('att')

        print(f"\n[*] Lancement ARP spoof : targets={args.targets} spoof={args.spoof} iface={args.iface}")
        start_arp_spoof(att, args.targets, args.spoof, iface=args.iface)
    
        CLI(net)

    except Exception as e:
        print(f"[!] Erreur: {e}")

    finally:
        if net:
            print("[*] Nettoyage : arrêt de l'ARP spoof et arrêt du réseau.")
            try:
                stop_arp_spoof(net.get('att'))
            except Exception as e:
                print("[!] Erreur lors du stop_arp_spoof:", e)
            net.stop()

if __name__ == '__main__':
    main()
