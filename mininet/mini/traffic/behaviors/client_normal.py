#!/usr/bin/env python3

"""
client_normal.py

Usage :
  python3 client_normal.py --server 10.0.1.10
  python3 client_normal.py --server 10.0.1.10 --target 10.0.1.20
  python3 client_normal.py --server 10.0.1.10 --min-wait 2 --max-wait 5

Ce script simule un comportement utilisateur normal :
 - Requêtes HTTP régulières (curl) vers --server
 - Pings occasionnels vers --target (1 chance sur 3)
 - Pause aléatoire entre actions (entre --min-wait et --max-wait)
 - Boucle infinie jusqu'à interruption (Ctrl+C ou kill)
"""

import argparse
import requests
from pythonping import ping
import random
import time
import sys


def http_request(server_ip, timeout=2):
    """Envoie une requête HTTP GET."""
    try:
        requests.get(f"http://{server_ip}", timeout=timeout)
    except Exception as e:
        print(f"[HTTP-ERR] {e}", file=sys.stderr)


def ping_once(target_ip):
    """Envoie un ping via pythonping (ICMP)."""
    print("--ping")
    try:
        ping(target_ip, count=1, timeout=2, verbose=False)
    except Exception as e:
        print(f"[PING-ERR] {e}", file=sys.stderr)


def user_behavior_loop(server_ip, target_ip, min_wait, max_wait):
    print(f"[+] User behavior started: HTTP={server_ip}, PING={target_ip}")

    while True:
        # requête HTTP
        http_request(server_ip)

        # ping 1 fois sur 3
        if random.randint(0, 2) == 0:
            ping_once(target_ip)

        # pause aléatoire
        time.sleep(random.randint(min_wait, max_wait))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server", required=True,
                        help="IP du serveur HTTP")
    parser.add_argument("--target", help="IP pour le ping (défaut = server)")
    parser.add_argument("--min-wait", type=int, default=1)
    parser.add_argument("--max-wait", type=int, default=3)
    args = parser.parse_args()

    target_ip = args.target if args.target else args.server

    user_behavior_loop(
        args.server,
        target_ip,
        args.min_wait,
        args.max_wait
    )


if __name__ == "__main__":
    main()
