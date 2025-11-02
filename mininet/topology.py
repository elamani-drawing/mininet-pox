from mininet.net import Mininet
from mininet.node import RemoteController, UserSwitch   
from mininet.link import TCLink
from mininet.topo import Topo
from mininet.log import setLogLevel, info
from mininet.cli import CLI

class TwoSubnetTopo(Topo):
    """
    Topologie Mininet : deux sous-réseaux séparés par un routeur.
    - Sous-réseau 1 (10.0.1.0/24) : serveur web (cible DoS) + 2 generateurs de trafic
    - Sous-réseau 2 (10.0.2.0/24) : 2 clients HTTP + attaquant (DoS / ARP spoof)
    - Chaque sous-réseau connecté à un switch OpenFlow (switch1, switch2)
    - Un routeur (router1) relie les deux sous-réseaux et fait du routage inter-VLAN
    - Contrôleur SDN distant : POX, résolu via le nom de service Docker 'pox'
    """
    def build(self):
        # Switches OpenFlow (nom explicite)
        switch1 = self.addSwitch('switch1')  # switch pour le sous-réseau 1
        switch2 = self.addSwitch('switch2')  # switch pour le sous-réseau 2

        # Sous-réseau 1 (10.0.1.0/24) : serveur cible + 2 generateurs de trafic
        # On donne des adresses MAC explicites (optionnel)
        srv  = self.addHost('srv',  ip='10.0.1.10/24', mac='00:00:00:00:01:10')  # serveur web (cible DoS)
        tg1  = self.addHost('tg1',  ip='10.0.1.11/24', mac='00:00:00:00:01:11')  # traffic generator 1
        tg2  = self.addHost('tg2',  ip='10.0.1.12/24', mac='00:00:00:00:01:12')  # traffic generator 2

        # Sous-réseau 2 (10.0.2.0/24) : 2 clients HTTP + attaquant
        cli1 = self.addHost('cli1', ip='10.0.2.10/24', mac='00:00:00:00:02:10')  # client HTTP 1
        cli2 = self.addHost('cli2', ip='10.0.2.11/24', mac='00:00:00:00:02:11')  # client HTTP 2
        att  = self.addHost('att',  ip='10.0.2.20/24', mac='00:00:00:00:02:20')  # attaquant (DoS / ARP spoof)

        # Routeur : host utilisé comme routeur (il aura deux interfaces, une par sous-réseau)
        router1 = self.addHost('router1', ip='10.0.1.1/24')  # on ajoutera la 2ème IP plus bas

        # Liens entre hosts et switches
        self.addLink(srv,  switch1)
        self.addLink(tg1,  switch1)
        self.addLink(tg2,  switch1)

        self.addLink(cli1, switch2)
        self.addLink(cli2, switch2)
        self.addLink(att,  switch2)

        # Lier le routeur aux deux switches (interfaces router1-eth0 et router1-eth1)
        self.addLink(router1, switch1)
        self.addLink(router1, switch2)

def run():
    setLogLevel('info')

    # Créer la topologie
    topo = TwoSubnetTopo()

    # Initialiser Mininet : on passe la classe RemoteController (pour POX)
    net = Mininet(topo=topo, controller=None, switch=UserSwitch , link=TCLink, autoSetMacs=True)

    # Ajouter le contrôleur distant (nom resolvable via docker-compose : 'pox-controller')
    c0 = net.addController('c0', controller=RemoteController, ip='pox', port=6633)

    # Démarrer le réseau
    net.start()

    info('\n*** Configuration des interfaces du routeur (router1)\n')
    r = net.get('router1')
    # router1-eth0 est connecté à switch1 (sous-réseau 10.0.1.0/24)
    # router1-eth1 est connecté à switch2 (sous-réseau 10.0.2.0/24)
    r.cmd('ifconfig router1-eth0 10.0.1.1/24 up')
    r.cmd('ifconfig router1-eth1 10.0.2.1/24 up')   # ajout de la 2ème IP pour le sous-réseau 2
    # Activer le routage IPv4 sur le routeur
    r.cmd('sysctl -w net.ipv4.ip_forward=1')

    info('\n*** Configuration des routes par défaut sur les hôtes\n')
    # Tous les hôtes pointent leur gateway vers l'adresse du router pour leur sous-réseau
    net.get('srv').cmd('ip route add default via 10.0.1.1 dev srv-eth0')
    net.get('tg1').cmd('ip route add default via 10.0.1.1 dev tg1-eth0')
    net.get('tg2').cmd('ip route add default via 10.0.1.1 dev tg2-eth0')

    net.get('cli1').cmd('ip route add default via 10.0.2.1 dev cli1-eth0')
    net.get('cli2').cmd('ip route add default via 10.0.2.1 dev cli2-eth0')
    net.get('att').cmd('ip route add default via 10.0.2.1 dev att-eth0')

    info('\n*** Démarrage d\'un serveur HTTP simple sur srv (cible DoS : 10.0.1.10)\n')
    server = net.get('srv')
    server.cmd('python3 -m http.server 80 &')

    info('\n*** Topologie prête — entrée en CLI Mininet (tape "exit" pour quitter)\n')
    CLI(net)

    info('\n*** Arrêt du réseau\n')
    net.stop()

if __name__ == '__main__':
    run()
