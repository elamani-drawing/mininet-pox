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
    && rm -rf /var/lib/apt/lists/*

# Implémentation OpenFlow mininet
RUN git clone https://github.com/mininet/openflow.git /tmp/openflow && \
    cd /tmp/openflow && ./boot.sh && ./configure && make && make install && \
    rm -rf /tmp/openflow

CMD ["bash"]
