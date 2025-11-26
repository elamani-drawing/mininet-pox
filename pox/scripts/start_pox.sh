#!/bin/bash
set -e
echo "Starting POX controller..."
echo "Attention ce POX Controller ne fait que de recevoi les packets, les afficher et les livrer..."
python3 pox.py detect forwarding.l2_learning log.level