#!/bin/bash
set -e
echo "Starting POX controller with forest firewall ..."
python3 pox.py forest_firewall forwarding.l2_learning log.level