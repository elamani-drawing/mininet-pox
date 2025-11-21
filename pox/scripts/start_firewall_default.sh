#!/bin/bash
set -e
echo "Starting POX controller with default firewall (analytical firewall)..."
python3 pox.py default_firewall log.level