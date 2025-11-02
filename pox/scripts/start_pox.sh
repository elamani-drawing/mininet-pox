#!/bin/bash
set -e
echo "Starting POX controller..."
python3 pox.py detect forwarding.l2_learning log.level