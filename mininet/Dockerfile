FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    git \
    build-essential \
    autoconf \
    automake \
    libtool \
    pkg-config \
    python3 \
    python3-pip \
    iproute2 \
    iputils-ping \
    net-tools \
    curl \
    sudo \
    mininet \
    tcpdump \
    wget \
    dos2unix \
    traceroute \
    openvswitch-switch \
    openvswitch-common \
    && rm -rf /var/lib/apt/lists/*

# Implémentation OpenFlow mininet
RUN git clone https://github.com/mininet/openflow.git /tmp/openflow && \
    cd /tmp/openflow && ./boot.sh && ./configure && make && make install && \
    rm -rf /tmp/openflow

RUN pip3 install mininet scapy netifaces requests pythonping

RUN mkdir /home/mininet
# COPY ./mini/ /home/mininet
WORKDIR /home/mininet

# Convertir tous les fichiers .sh vers Unix et demarre OVS au demarage du conteneur
ENTRYPOINT ["bash", "-c", "find /home/mininet -type f -name '*.sh' -exec dos2unix {} \\; && bash /home/mininet/start_ovs.sh"]