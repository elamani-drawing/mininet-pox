#!/bin/bash
set -e

# Ensure directories exist
mkdir -p /var/run/openvswitch
mkdir -p /var/log/openvswitch
mkdir -p /etc/openvswitch

# Initialize DB if missing
if [ ! -f /etc/openvswitch/conf.db ]; then
    ovsdb-tool create /etc/openvswitch/conf.db /usr/share/openvswitch/vswitch.ovsschema
fi

# Start OVS DB
ovsdb-server --remote=punix:/var/run/openvswitch/db.sock \
             --remote=db:Open_vSwitch,Open_vSwitch,manager_options \
             --pidfile=/var/run/openvswitch/ovsdb-server.pid \
             --detach

# Wait server
sleep 0.5

# Start OVS switch daemon
ovs-vswitchd unix:/var/run/openvswitch/db.sock \
             --pidfile=/var/run/openvswitch/ovs-vswitchd.pid \
             --detach

echo "[OK] Open vSwitch is running"

exec bash
