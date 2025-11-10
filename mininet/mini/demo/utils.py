import os
import shlex

DIR_SCRIPT = "/home/mininet/mini/att/"
SCRIPT_ARP  = DIR_SCRIPT+"arp_spoof.py"
SCRIPT_HTTP = DIR_SCRIPT+"dos_http_flood.py" 
SCRIPT_SYN  = DIR_SCRIPT+"dos_syn_flood.py"

def ensure_script_exists(script_path):
    if not os.path.exists(script_path):
        raise FileNotFoundError(f"{script_path} introuvable sur la machine hôte.")
    # rendre exécutable côté hôte
    os.chmod(script_path, 0o755)

def start_http_flood(att, target_ip, port=80, threads=10, reqs=1000, log="/tmp/http_flood.log"):
    """
    Démarre le script de flood HTTP sur l'hôte 'att'.
    Usage attendu du script : python3 dos_http_flood.py <target_ip> <port> <threads> <requests_per_thread>
    """
    ensure_script_exists(SCRIPT_HTTP)
    # rendre exécutable côté mininet host (idempotent)
    att.cmd(f"chmod +x {SCRIPT_HTTP} || true")

    # Construire la commande avec échappement sûr
    args = f"{shlex.quote(str(target_ip))} {shlex.quote(str(port))} {shlex.quote(str(threads))} {shlex.quote(str(reqs))}"
    # Lancer détaché (setsid) et rediriger stdout/stderr
    cmd = f"setsid python3 {SCRIPT_HTTP} {args} > {log} 2>&1"
    att.popen(cmd)
    print(f"[*] HTTP flood lancé sur att -> cible {target_ip}:{port} (threads={threads}, reqs={reqs}). Log: {log}")
    print(f"[*] CMD: {cmd} &")
    
    print("[*] Observer l'attaque avec: 'srv tcpdump -i srv-eth0 port 80' ou sur pox .")
    print("[*] Retrouver le <PID> du processus à l'aide de : 'att pgrep -af dos_http_flood.py'")
    print("[*] Arreter l'attaque et netoyer les tables : att kill -2 <PID>")
    print("[*] Arreter l'attaque sans netoyer les tables :  att kill <PID> ou att kill -9 <PID>.")

def stop_http_flood(att):
    """
    Tue tout processus Python qui exécute le script HTTP flood.
    """
    # On recherche par chemin du script (plus précis que pkill -f 'python3')
    att.cmd(f"pkill -f '{SCRIPT_HTTP}' || true")
    print("[*] http_flood arrêté (si présent).")

def start_arp_spoof(att, targets_csv, spoof_ip, iface='att-eth0', log="/tmp/arp_spoof.log"):
    """
    Démarre le script d'ARP spoof sur 'att'.
    targets_csv : chaîne '10.0.2.10,10.0.2.11'
    spoof_ip    : ip à usurper (ex: 10.0.2.1)
    iface       : interface utilisée par att (ex: att-eth0)
    Usage attendu du script : python3 arp_spoof.py <target_ip1,target_ip2,...> <spoof_ip> <iface>
    """
    ensure_script_exists(SCRIPT_ARP)
    att.cmd(f"chmod +x {SCRIPT_ARP} || true")
    # Activer ip_forward pour MITM transparent
    att.cmd("sysctl -w net.ipv4.ip_forward=1")

    args = f"{shlex.quote(str(targets_csv))} {shlex.quote(str(spoof_ip))} {shlex.quote(str(iface))}"
    cmd = f"setsid python3 {SCRIPT_ARP} {args} > {log} 2>&1"
    att.popen(cmd)
    
    print(f"[*] ARP spoof lancé sur att -> targets={targets_csv} spoof_ip={spoof_ip} iface={iface}. Log: {log}")
    print(f"[*] CMD: {cmd} &")
    
    print("[*] Observer l'attaque avec: 'cli1 arp -n' .")
    print("[*] Retrouver le <PID> du processus à l'aide de : 'att pgrep -af arp_spoof.py'")
    print("[*] Arreter l'attaque et netoyer les tables : att kill -2 <PID>")
    print("[*] Arreter l'attaque sans netoyer les tables :  att kill <PID> ou att kill -9 <PID>.")

def stop_arp_spoof(att):
    """
    Tue le script d'ARP spoof s'il tourne.
    """
    att.cmd(f"pkill -f '{SCRIPT_ARP}' || true")
    print("[*] arp_spoof arrêté (si présent).")

def start_syn_flood(att, target_ip, port=80, iface='att-eth0', log="/tmp/syn_flood.log"):
    """
    Démarre le script dos_syn_flood.py sur l'hôte 'att'.
    Usage attendu du script : python3 dos_syn_flood.py <target_ip> <port> <iface>
    """
    ensure_script_exists(SCRIPT_SYN)
    att.cmd(f"chmod +x {SCRIPT_SYN} || true")
    # Construction des arguments en échappant
    args = f"{shlex.quote(str(target_ip))} {shlex.quote(str(port))} {shlex.quote(str(iface))}"
    cmd = f"setsid python3 {SCRIPT_SYN} {args} > {log} 2>&1"
    att.popen(cmd)
    print(f"[*] SYN flood lancé sur att -> cible {target_ip}:{port} via iface {iface}. Log: {log}")
    print(f"[*] CMD: {cmd} &")

    print("[*] Observer l'attaque avec: 'srv tcpdump -i srv-eth0 port 80', 'srv ss -s -ant' ou sur pox .")
    print("[*] Retrouver le <PID> du processus à l'aide de : att pgrep -af dos_syn_flood.py")
    print("[*] Arreter l'attaque et netoyer les tables: att kill -2 <PID>")
    print("[*] Arreter l'attaque sans netoyer les tables:  att kill <PID> ou att kill -9 <PID>.")

def stop_syn_flood(att):
    """
    Tue le script dos_syn_flood.py s'il tourne.
    """
    att.cmd(f"pkill -f '{SCRIPT_SYN}' || true")
    print("[*] syn_flood arrêté (si présent).")