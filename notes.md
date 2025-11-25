# lancer les conteneurs
docker-compose up --build -d
docker-compose build --no-cache -d
docker ps -a (afficher tout les conteneur)
docker container prune (supprimer tout les conteneur stopper)

# entrer dans les conteneurs
docker exec -it mininet bash          
docker exec -it pox  bash


# attaques dos http flood

att python3 /home/mininet/mini/att/dos_syn_flood.py srv 80 att-eth0 > /tmp/syn_flood.log 2>&1 &
regarder les entrée sur le serveur
srv tcpdump -i srv-eth0 port 80
att pgrep -af dos_syn_flood.py
att kill <PID>
verifier que le serveur est lancer 

srv  pgrep -af python

# attaques dos syn flood
att python3 /home/mininet/mini/att/dos_http_flood.py srv 80 20 1000  > /tmp/syn_flood.log 2>&1
att pgrep -af dos_http_flood.py
regarder les stats sur 
srv ss -ltnp | grep :80
srv ss -ant | grep ':80' | wc -l
att kill <PID>


# demo arp
python3 -m mini.demo.arp_spoof --targets 10.0.2.10,10.0.2.11 --spoof 10.0.2.1 --iface att-eth0 > /tmp/arp_spoof.log 2>&1 &
att python3 /home/mininet/mini/att/arp_spoof.py  10.0.2.10 10.0.2.1 att-eth0 > /tmp/arp_spoof.log 2>&1 &
att pgrep -af arp_spoof.py
att kill <PID>
srv arp -n
vider le cache arp 
cli1 ip -s -s neigh flush all
