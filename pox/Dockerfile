FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    git \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Installer POX
RUN git clone https://github.com/noxrepo/pox.git /pox

WORKDIR /pox

# CMD ["python3", "pox.py", "forwarding.l2_learning"]
CMD ["bash"]