#!/usr/bin/env python3

"""
ping_loop.py

Usage :
  python3 ping_loop.py --target 10.0.1.10
  python3 ping_loop.py --target 10.0.1.10 --interval 2.5

Ce script :
 - Ping continuellement l'IP spécifiée
 - Intervalle configurable entre chaque ping
 - Boucle infinie jusqu'à interruption (Ctrl+C)
"""

import argparse
import time
import sys
from pythonping import ping

def ping_loop(target_ip, interval=1.0):
    """Ping continu vers target_ip avec pause intervalaire"""
    print(f"[+] Starting ping loop to {target_ip}, interval={interval}s")
    try:
        while True:
            try:
                ping(target_ip, count=1, timeout=2, verbose=True)
            except Exception as e:
                print(f"[PING-ERR] {e}", file=sys.stderr)
            time.sleep(interval)
    except KeyboardInterrupt:
        print("\n[!] Ping loop stopped.")
        sys.exit(0)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", required=True, help="IP à pinguer")
    parser.add_argument("--interval", type=float, default=1.0, help="Intervalle entre chaque ping (secondes)")
    args = parser.parse_args()

    ping_loop(args.target, args.interval)


if __name__ == "__main__":
    main()
