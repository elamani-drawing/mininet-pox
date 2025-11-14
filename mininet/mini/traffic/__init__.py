import shlex
import os

def _safe_quote(x):
    return shlex.quote(str(x))

def _popen_detached(host, cmd, log="/tmp/traffic_default.log"):
    """
    Lance la commande cmd détachée (setsid) sur le host Mininet et redirige stdout/stderr vers log.
    host.popen attend une string (comme dans ton exemple).
    """
    # Construire la commande finale (comme dans ton exemple)
    final = f"setsid bash -c { _safe_quote(cmd + ' > ' + log + ' 2>&1') }"
    print(f"==${host.name}==Execution de ${final}")
    return host.popen(final)

# Servers ---------------------------------------------------------------------
def start_http_server(host, port=8080, log="/tmp/http_server.log"):
    """
    Lance `python3 -m http.server {port}` en arrière-plan sur host.
    """
    cmd = f"python3 -m http.server { _safe_quote(port) }"
    # s'assurer que le fichier existe 
    return _popen_detached(host, cmd, log=log)

def start_iperf_server(host, port=5002, log="/tmp/iperf_server.log"):
    """
    Lance iperf en mode serveur (tcp) sur host.
    """
    # iperf v2 par défaut : iperf -s [-p port]
    cmd = f"iperf -s -p { _safe_quote(port) }"
    return _popen_detached(host, cmd, log=log)

# Clients / generators -------------------------------------------------------
def start_http_loop_client(host, target_ip, port=8080, delay=0.8, log="/tmp/http_client_loop.log"):
    """
    Boucle infinie curl -> simule navigation régulière.
    """
    cmd = f"while true; do curl -s http://{_safe_quote(target_ip)}:{_safe_quote(port)} >/dev/null; sleep { _safe_quote(delay) }; done"
    return _popen_detached(host, cmd, log=log)

def start_ping_loop(host, target_ip, delay=5.0, log="/tmp/ping_loop.log"):
    """
    Envoie un ping toutes les `delay` secondes.
    """
    cmd = f"while true; do ping -c 1 -W 1 { _safe_quote(target_ip) } >/dev/null; sleep { _safe_quote(delay) }; done"
    return _popen_detached(host, cmd, log=log)

def start_iperf_burst_loop(host, server_ip, duration=10, parallel=1, sleep_between=20, log="/tmp/iperf_burst.log"):
    """
    Lance périodiquement iperf client (bursts) pour simuler charges normales.
    - duration : durée iperf en secondes (-t)
    - parallel : nombre de streams (-P)
    - sleep_between : pause entre deux bursts
    """
    cmd = f"while true; do iperf -c {_safe_quote(server_ip)} -t {_safe_quote(duration)} -P {_safe_quote(parallel)} >/dev/null; sleep {_safe_quote(sleep_between)}; done"
    return _popen_detached(host, cmd, log=log)

def start_udp_generator(host, target_ip, target_port=5001,
                        min_size=40, max_size=400, max_sleep=0.6, log="/tmp/udp_gen.log"):
    """
    Générateur UDP simple en Python via heredoc (spawné sur l'hôte Mininet).
    Envoie des paquets UDP aléatoires de taille entre min_size et max_size.
    """
    py_script = (
        "import socket, time, random\n"
        "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
        f"dst = ({_safe_quote(target_ip)}, {_safe_quote(target_port)})\n"
        "while True:\n"
        f"    s.sendto(b'x'*random.randint({min_size},{max_size}), dst)\n"
        "    time.sleep(random.random()*%s)\n" % (max_sleep)
    )

    # Construire une commande heredoc (bash -c) contenant le script Python
    # On utilise <<'PY' pour empêcher expansion par le shell de l'interpréteur hôte.
    cmd = f"python3 -u - <<'PY'\n{py_script}\nPY"
    return _popen_detached(host, cmd, log=log)

# Utility / stop --------------------------------------------------------------
def stop_traffic(host):
    """
    Tente d'arrêter les processus lancés (curl, iperf, http.server, scripts python).
    Utilise pkill -f qui est simple et idempotent.
    """
    # commandes de nettoyage (ignorer les erreurs)
    cmds = [
        "pkill -f curl || true",
        "pkill -f iperf || true",
        "pkill -f http.server || true",
        "pkill -f python3 || true",
        "pkill -f 'setsid' || true"
    ]
    return host.cmd(" ; ".join(cmds))

# High-level helper to start a profile on multiple hosts ---------------------
def start_normal_profile(net, servers=("srv", "tg1", "tg2"), clients=("cli1", "cli2")):
    """
    Démarre un profil 'normal' complet :
      - HTTP + iperf servers sur hosts listés dans servers
      - clients exécutent curl loops, ping loops et iperf bursts
    Retourne un dict { host_name: popen_object_or_None }
    """
    procs = {}
    # serveurs
    for s in servers:
        h = net.get(s)
        procs[f"{s}_http"] = start_http_server(h, port=8080, log=f"/tmp/{s}_http.log")
        procs[f"{s}_iperf"] = start_iperf_server(h, port=5001, log=f"/tmp/{s}_iperf.log")

    # clients
    for i, c in enumerate(clients):
        h = net.get(c)
        procs[f"{c}_http_loop"] = start_http_loop_client(h, target_ip=net.get("srv").IP(), port=8080,
                                                         delay=0.7 + 0.5*i, log=f"/tmp/{c}_http_loop.log")
        procs[f"{c}_ping"] = start_ping_loop(h, target_ip=net.get("srv").IP(), delay=5 + 2*i, log=f"/tmp/{c}_ping.log")
        procs[f"{c}_iperf_burst"] = start_iperf_burst_loop(h, server_ip=net.get("srv").IP(),
                                                           duration=10, parallel=1+i, sleep_between=20+5*i,
                                                           log=f"/tmp/{c}_iperf_burst.log")
        procs[f"{c}_udp"] = start_udp_generator(h, target_ip=net.get("srv").IP(), target_port=5001,
                                                min_size=40, max_size=400, max_sleep=0.6 + 0.2*i,
                                                log=f"/tmp/{c}_udp.log")
    return procs
