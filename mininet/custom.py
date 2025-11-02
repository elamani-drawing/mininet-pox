#!/usr/bin/python3
# -*- coding: utf-8 -*-
from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink
from mininet.cli import CLI

class CustomTopo(Topo):
    def build(self):
        # Switchs
        s1 = self.addSwitch('s1')
        s2 = self.addSwitch('s2')

        # Routeur (entre les sous-réseaux)
        r1 = self.addHost('r1', ip='10.0.0.1/24')

        # Sous-réseau 1
        web = self.addHost('web', ip='10.0.0.2/24')
        gen1 = self.addHost('gen1', ip='10.0.0.3/24')
        gen2 = self.addHost('gen2', ip='10.0.0.4/24')

        # Sous-réseau 2
        client1 = self.addHost('c1', ip='10.0.1.2/24')
        client2 = self.addHost('c2', ip='10.0.1.3/24')
        attacker = self.addHost('att', ip='10.0.1.4/24')

        # Liens
        self.addLink(s1, web)
        self.addLink(s1, gen1)
        self.addLink(s1, gen2)
        self.addLink(s2, client1)
        self.addLink(s2, client2)
        self.addLink(s2, attacker)
        self.addLink(s1, r1)
        self.addLink(s2, r1)

topos = {'customtopo': (lambda: CustomTopo())}
