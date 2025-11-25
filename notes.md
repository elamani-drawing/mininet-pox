# lancer les conteneurs
docker-compose up --build -d
docker-compose build --no-cache -d

# entrer dans les conteneurs
docker exec -it mininet bash          
docker exec -it pox  bash

# Lancer pox et mininet
python3 pox.py detect forwarding.l2_learning 
python3 topology.py
tu peux:  pingall dans mininet

# autres
mn --custom custom.py --topo customtopo --controller=remote,ip:172.20.0.2 --switch user --link tc
python3 pox.py detect

att python3 /home/mininet/mini/att/dos_syn_flood.py srv 80 att-eth0 > /tmp/syn_flood.log 2>&1 &
att python3 /home/mininet/mini/att/dos_http_flood.py srv 80 20 1000  > /tmp/syn_flood.log 2>&1

srv ss -ltnp | grep :80
srv ss -ant | grep ':80' | wc -l

dos http 

srv tcpdump -i srv-eth0 port 80
<!-- srv tcpdump -i srv-eth0 tcp port 80 -->


# demo arp
python3 -m mini.demo.arp_spoof --targets 10.0.2.10,10.0.2.11 --spoof 10.0.2.1 --iface att-eth0 > /tmp/arp_spoof.log 2>&1 &
att python3 /home/mininet/mini/att/arp_spoof.py  10.0.2.10 10.0.2.1 att-eth0 > /tmp/arp_spoof.log 2>&1 &
att pgrep -af arp_spoof.py
att kill <PID>
srv arp -n

cli1 ip -s -s neigh flush all

att python3 /home/mininet/mini/att/arp_spoof.py  10.0.2.10,10.0.2.11 10.0.2.1 att-eth0 

srv  pgrep -af python

generer un trafic, generer le model,  annalyser le trafic, 

setsid bash -c 'setsid python3 /home/mininet/mini/traffic/client_behavior.py --server 10.0.1.10 --target 10.0.2.10  > /tmp/mixed_behavior.log 2>&1' &


trouver pk le server web reste innacessible 

docker ps -a (afficher tout les conteneur)
docker container prune (supprimer tout les conteneur stopper)

service openvswitch-switch status

ovs-vsctl --version
mn --topo tree,2 --switch ovsk --controller=remote
mn --switch ovsk --test pingall


cli1 pgrep -af python