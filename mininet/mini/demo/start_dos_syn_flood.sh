#!/bin/bash
set -e
# Wait for POX controller on host 'pox' port 6633
echo "Lancement de mininet et de l'attaque DOS SYN FLOOD..."
for i in {1..60}; do
  if command -v nc >/dev/null 2>&1; then
    if nc -z pox 6633; then
      echo "POX is up"
      break
    fi
  else
    # fallback using /dev/tcp (bash)
    (echo > /dev/tcp/pox/6633) >/dev/null 2>&1 && { echo "POX is up"; break; } || true
  fi
  echo "Waiting... ($i)"
  sleep 1
done

# Lancer Mininet
python3 -m mini.demo.dos_syn_flood --target 10.0.1.10 --port 80 --iface att-eth0

