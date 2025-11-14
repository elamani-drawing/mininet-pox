#!/usr/bin/env python3
import shlex

DIR_SCRIPT = "/home/mininet/mini/traffic/behaviors/"
SCRIPT_CLIENT_NORMAL  = DIR_SCRIPT+"client_normal.py"
SCRIPT_HTTP_LOOP = DIR_SCRIPT+"http_loop.py"
SCRIPT_PING_LOOP  = DIR_SCRIPT+"ping_loop.py"

def _safe_quote(x):
    return shlex.quote(str(x))

def _popen_detached(host, cmd, log="/tmp/traffic_default.log"):
    """
    Lance un process sur un host
    Args:
        host: host Mininet
        cmd: string de la commande à exécuter
        log: fichier pour stdout/stderr
    
    Returns:
        subprocess.Popen
    """
    print(f"- [{host.name}] EXEC: {cmd} -> {log}")
    f = open(log, "w")  # ouvre le log pour host.popen
    return host.popen(cmd, stdout=f, stderr=f)

def _popen_bash(host, args, log="/tmp/traffic_default.log"):
    """
    Lance un script ou commande bash sur un host Mininet.
    
    Args:
        host: host Mininet
        args: string de la commande bash
        log: fichier pour stdout/stderr
    
    Returns:
        subprocess.Popen
    """
    # Utiliser shlex.quote pour sécuriser la commande
    final = f"bash -c {_safe_quote(args)}"
    return _popen_detached(host, final, log)

def start_http_loop(host, server_ip, min_wait=1, max_wait=3, timeout=2, log="/tmp/http_loop.log"):
    """
    Lance une boucle de requêtes HTTP aléatoires depuis un host Mininet.
    
    Args:
        host: host Mininet
        server_ip: IP/URL du serveur HTTP
        min_wait: pause minimale entre les requêtes
        max_wait: pause maximale entre les requêtes
        timeout: timeout HTTP
        log: fichier log pour stdout/stderr

    Returns:
        subprocess.Popen
    """
    host.cmd(f"chmod +x {SCRIPT_HTTP_LOOP} || true")

    args = (
        f"--target {_safe_quote(server_ip)} "
        f"--min-wait {_safe_quote(min_wait)} "
        f"--max-wait {_safe_quote(max_wait)} "
        f"--timeout {_safe_quote(timeout)}"
    )
    cmd = f"python3 {SCRIPT_HTTP_LOOP} {args}"
    return _popen_detached(host, cmd, log)


def start_ping_loop(host, target_ip, interval=1.0, log="/tmp/ping_loop.log"):
    """
    Lance un ping léger en continu depuis un host Mininet.

    Args:
        host: host Mininet
        target_ip: IP à pinguer
        interval: temps entre chaque ping (secondes)
        log: fichier log pour stdout/stderr

    Returns:
        subprocess.Popen
    """
    host.cmd(f"chmod +x {SCRIPT_PING_LOOP} || true")

    args = f"--target {_safe_quote(target_ip)} --interval {_safe_quote(interval)}"

    cmd = f"python3 {SCRIPT_PING_LOOP} {args}"
    return _popen_detached(host, cmd, log)



def run_normal_iperf(net, client, server, duration=10):
    """
    Utilise l’API native Mininet net.iperf().
    """
    return net.iperf((client, server), seconds=duration)


def start_mixed_user_behavior(host, server_ip, target_ip=None,   log="/tmp/mixed_behavior.log"):
    """
    Comportement mixte : HTTP + ping aléatoire.
    """
    if target_ip is None:
        target_ip = server_ip

    host.cmd(f"chmod +x {SCRIPT_CLIENT_NORMAL} || true")

    args = f"--server {_safe_quote(server_ip)} --target {_safe_quote(target_ip)}"

    cmd = f"python3 {SCRIPT_CLIENT_NORMAL} {args}"
    return _popen_detached(host, cmd, log)


