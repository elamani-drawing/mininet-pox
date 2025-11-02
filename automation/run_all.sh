#!/bin/bash
set -e
echo "Building and starting containers..."
docker-compose up --build -d
echo "Waiting 5s for services to stabilize..."
sleep 5
echo "To run the demo:
 - Attach to the mininet container: docker exec -it mininet-node bash
 - From inside mininet container, attacker host is h6, start attacks with:
    python3 /opt/mininet/arp_spoof.py 10.0.2.10 10.0.2.1 &
    python3 /opt/mininet/dos_attack.py 10.0.1.10 udp 80 200 &
 - You can watch POX logs in the pox container: docker logs -f pox-controller
 - To stop: docker-compose down
"
