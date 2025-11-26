FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    git \
    python3 \
    python3-pip \
    dos2unix \
    && rm -rf /var/lib/apt/lists/*

# Installer POX
RUN git clone https://github.com/noxrepo/pox.git /pox


RUN pip3 install pandas scikit-learn joblib numpy

WORKDIR /pox

# Copie les script pox dans /pox
COPY ./scripts/ /pox

# Convertir tous les fichiers .sh du dossier /pox en format Unix
RUN find /pox -type f -name "*.sh" -exec dos2unix {} \;

# CMD ["python3", "pox.py", "forwarding.l2_learning"]
CMD ["bash"]