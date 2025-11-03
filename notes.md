# lancer les conteneurs
docker-compose up --build -d
docker-compose up --build --no-cache -d

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