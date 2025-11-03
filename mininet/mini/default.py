#!/usr/bin/env python3

from mini.topology import create_network
from mininet.cli import CLI


if __name__ == '__main__':
    net = create_network()
    print('\n*** Réseau démarré. Observe et interagis via la CLI Mininet')
    CLI(net)
    print('\n*** Arrêt du réseau')
    net.stop()