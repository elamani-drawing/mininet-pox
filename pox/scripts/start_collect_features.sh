#!/bin/bash
set -e
echo "Starting POX controller with feature collection..."
python3 pox.py collect_features forwarding.l2_learning log.level