# Projet de Simulation de Réseau avec Mininet et POX

Ce projet met en place un environnement de simulation réseau utilisant Mininet pour créer une topologie réseau virtuelle et POX comme contrôleur SDN. L'objectif est de simuler diverses attaques réseau et de mettre en œuvre des mécanismes de détection et de prévention.

## Structure du Projet

Le projet est organisé comme suit :

-   `mininet/` : Contient la configuration de l'environnement Mininet, y compris la topologie du réseau, les scripts d'attaque et les générateurs de trafic.
-   `pox/` : Contient les modules du contrôleur POX, y compris les mécanismes de défense comme les pare-feu et un système de détection d'intrusion basé sur le Machine Learning.
-   `automation/` : Scripts pour automatiser certaines tâches.
-   `docker-compose.yml` : Fichier de configuration pour orchestrer les conteneurs Mininet et POX.

## Démarrage Rapide

### Prérequis

-   [Docker](https://docs.docker.com/get-docker/)
-   [Docker Compose](https://docs.docker.com/compose/install/)

### Installation

1.  Clonez le dépôt.
2.  Construisez et lancez les conteneurs en mode détaché :

    ```bash
    docker-compose up --build -d
    ```

    Pour forcer la reconstruction des images sans utiliser le cache :

    ```bash
    docker-compose up --build --no-cache -d
    ```

3.  Vérifiez que les conteneurs sont en cours d'exécution :

    ```bash
    docker ps -a
    ```

## Utilisation

### Accéder aux Conteneurs

Pour interagir avec les services, vous pouvez ouvrir un shell à l'intérieur des conteneurs :

-   **Conteneur Mininet** (pour lancer les attaques et générer du trafic) :

    ```bash
    docker exec -it mininet bash
    ```

-   **Conteneur POX** (où le contrôleur SDN s'exécute) :

    ```bash
    docker exec -it pox bash
    ```

### Lancer la Simulation

1.  **Démarrez le contrôleur POX** :
    Dans le conteneur `pox`, exécutez l'un des scripts de démarrage situés dans `/home/pox/scripts/` en fonction du module que vous souhaitez activer. Par exemple, pour démarrer un simple switch L2 :
    ```bash
    # A l'intérieur du conteneur pox
    /home/pox/scripts/start_pox.sh
    ```

2.  **Démarrez la topologie Mininet** :
    Dans le conteneur `mininet`, lancez le script pour créer le réseau :
    ```bash
    # A l'intérieur du conteneur mininet
    /home/mininet/start_mininet.sh
    ```

## Lancer les Attaques

Les scripts d'attaque doivent être lancés depuis le conteneur `mininet` avec la cli d'activer et la topologie déployer, par exemple avec `start_mininet.sh`.

### Attaque DoS - SYN Flood

Ce script lance une attaque par inondation SYN sur le serveur `srv`.

```bash
# Depuis le conteneur mininet, sur le nœud 'att'
att python3 /home/mininet/mini/att/dos_syn_flood.py srv 80 att-eth0 > /tmp/syn_flood.log 2>&1 &
```

Pour observer l'attaque sur le serveur :

```bash
# Sur le nœud 'srv'
srv tcpdump -i srv-eth0 port 80
```

### Attaque DoS - HTTP Flood

Ce script lance une attaque par inondation de requêtes HTTP.

```bash
# Depuis le conteneur mininet, sur le nœud 'att'
att python3 /home/mininet/mini/att/dos_http_flood.py srv 80 20 1000 > /tmp/http_flood.log 2>&1 &
```

Pour observer l'impact sur le serveur :

```bash
# Sur le nœud 'srv'
srv tcpdump -i srv-eth0 port 80
```

### Attaque ARP Spoofing

Ce script empoisonne le cache ARP des cibles pour rediriger le trafic.

```bash
# Depuis le conteneur mininet, sur le nœud 'att'
att python3 /home/mininet/mini/att/arp_spoof.py 10.0.2.10 10.0.2.1 att-eth0 > /tmp/arp_spoof.log 2>&1 &
```

Pour vérifier la table ARP sur une victime (par exemple `cli1` avec l'IP `10.0.2.10`) :

```bash
# Sur le nœud 'cli1'
cli1 arp -n
```

## Démos Automatisées

Il est également possible de lancer une simulation complète (topologie + attaque + CLI Mininet) en une seule commande depuis le conteneur `mininet`. Ces scripts de démonstration se trouvent dans `mini/demo`.

### ARP Spoof

```bash
# Depuis le conteneur mininet
python3 -m mini.demo.arp_spoof --targets <IP_VICTIME_1>,<IP_VICTIME_2> --spoof <IP_SPOOF> --iface <INTERFACE>
```
**Exemple :**
`python3 -m mini.demo.arp_spoof --targets 10.0.2.10,10.0.2.11 --spoof 10.0.2.1 --iface att-eth0`

### DoS HTTP Flood

```bash
# Depuis le conteneur mininet
python3 -m mini.demo.dos_http_flood --target <IP_CIBLE> --port <PORT_CIBLE> --threads <NB_THREADS> --reqs <NB_REQUETES>
```
**Exemple :**
`python3 -m mini.demo.dos_http_flood --target 10.0.1.10 --port 80 --threads 20 --reqs 1000`

### DoS SYN Flood

```bash
# Depuis le conteneur mininet
python3 -m mini.demo.dos_syn_flood --target <IP_CIBLE> --port <PORT_CIBLE> --iface <INTERFACE>
```
**Exemple :**
`python3 -m mini.demo.dos_syn_flood --target 10.0.1.10 --port 80 --iface att-eth0`

## Mécanismes de Défense (Contrôleur POX)

Le contrôleur POX peut être lancé avec différents modules de sécurité. Utilisez les scripts dans `/home/pox/scripts/` à l'intérieur du conteneur `pox`.

-   `start_firewall_default.sh`: Lance un pare-feu statique basique.
-   `start_firewall_forest.sh`: Lance un pare-feu dynamique utilisant un modèle d'Isolation Forest pour détecter et bloquer les attaques.
-   `start_collect_features.sh`: Active la collecte de caractéristiques du trafic réseau, qui sont sauvegardées dans `pox/tmp/pox_features.csv`.
-   `start_train_forest.sh`: Lance l'entraînement du modèle d'Isolation Forest à partir des données collectées.

## Nettoyage

Pour arrêter et supprimer les conteneurs, réseaux et volumes créés :

```bash
docker-compose down
```

Pour supprimer tous les conteneurs arrêtés :

```bash
docker container prune
```
