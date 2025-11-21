#!/usr/bin/env python3

from mini.topology import create_network
from mininet.cli import CLI
from mini.traffic.behavior import (
    start_http_loop,
    start_ping_loop,
    run_normal_iperf,
    start_mixed_user_behavior
)

def start_normal_traffic(net):
    """
    Démarre un ensemble réaliste de trafics normaux entre les hosts
    définis dans ta topologie.
    Retourne une liste des processus Popen lancés
    """
    # Les requetes http/tcp peuvent echouer si on est en user switch mode, retester avec ovs switch
    print("\n*** Lancement du trafic normal...")

    # Récupération des hosts
    srv  = net.get('srv')
    tg1  = net.get('tg1')
    tg2  = net.get('tg2')
    cli1 = net.get('cli1')
    cli2 = net.get('cli2')
    # att = net.get('att')  

    srv_ip = srv.IP()
    
    # on garde une trace de tous les popen
    processes = []  

    # Clients HTTP trafic web normal (CURL loops)
    processes.append(start_http_loop(cli1, srv_ip))
    processes.append(start_http_loop(cli2, srv_ip))

    # Traffic generators trafic “background”

    # tg1 effectue un mix réaliste (HTTP léger + ping occasionnel) 
    processes.append(start_mixed_user_behavior(tg1, srv_ip, cli1.IP()))

    # tg2 fait uniquement du HTTP très léger
    processes.append(start_http_loop(tg2, srv_ip, min_wait=2, max_wait=5))

    # tg1 et tg2 font un ping léger sur le serveur
    processes.append(start_ping_loop(tg1, srv_ip, interval=2))
    processes.append(start_ping_loop(tg2, srv_ip, interval=3))
    processes.append(start_ping_loop(cli1, srv_ip, interval=4))

    # Un petit iperf TCP occasionnel depuis tg1 srv pour simuler un trafic "upload" normal)
    # print("*** Lancement d'un iperf normal tg1 srv (10s)") 
    run_normal_iperf(net, tg1, srv, duration=10)


    print("*** Trafic normal en cours .")
    # print("--process", processes)
    return processes

if __name__ == '__main__':
    net = create_network() 
    processes = start_normal_traffic(net)  
    print([ (i,p.poll()) for i,p in enumerate(processes) ])  
    CLI(net)
    net.stop()
