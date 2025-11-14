#!/usr/bin/env python3

"""
http_loop.py

Usage:
  python3 http_loop.py --target http://10.0.1.10 --min-wait 1 --max-wait 5
  python3 http_loop.py --target 10.0.1.10 --min-wait 0 --max-wait 2 --timeout 2

Ce script :
 - Effectue une requête HTTP périodique vers une URL/serveur
 - Attend un délai aléatoire entre min_wait et max_wait (en secondes)
 - Boucle infinie jusqu'à Ctrl+C
"""

import argparse
import time
import sys
import random
import requests

def http_loop(target, min_wait, max_wait, timeout):
    """Boucle infinie envoyant des requêtes HTTP vers target."""
    # Permet d'accepter un target donné sans http://
    if not target.startswith("http://") and not target.startswith("https://"):
        url = "http://" + target
    else:
        url = target

    print(f"[+] Starting HTTP loop to {url}")
    print(f"[+] Random wait between {min_wait} and {max_wait} seconds")
    print(f"[+] Timeout = {timeout}s")

    try:
        while True:
            try:
                r = requests.get(url, timeout=timeout)
                print(f"[HTTP {r.status_code}] {len(r.content)} bytes")
            except Exception as e:
                print(f"[HTTP-ERR] {e}", file=sys.stderr)

            wait_time = random.uniform(min_wait, max_wait)
            time.sleep(wait_time)

    except KeyboardInterrupt:
        print("\n[!] HTTP loop stopped.")
        sys.exit(0)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True, help="URL ou IP à requêter")
    parser.add_argument("--min-wait", type=float, default=1.0, help="Temps d'attente min (secondes)")
    parser.add_argument("--max-wait", type=float, default=3.0, help="Temps d'attente max (secondes)")
    parser.add_argument("--timeout", type=float, default=2.0, help="Timeout des requêtes HTTP")

    args = parser.parse_args()

    if args.min_wait > args.max_wait:
        print("Erreur: min-wait doit être <= max-wait")
        sys.exit(1)

    http_loop(args.target, args.min_wait, args.max_wait, args.timeout)


if __name__ == "__main__":
    main()
