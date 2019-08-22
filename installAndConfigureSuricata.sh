#!/bin/bash
sudo apt-get -y install libpcre3 libpcre3-dbg libpcre3-dev \
build-essential autoconf automake libtool libpcap-dev libnet1-dev \
libyaml-0-2 libyaml-dev zlib1g zlib1g-dev libcap-ng-dev libcap-ng0 \
make libmagic-dev libjansson-dev libjansson4 pkg-config

wget https://www.openinfosecfoundation.org/download/suricata-4.1.4.tar.gz
tar -xf suricata-4.1.4.tar.gz
cd suricata-4.1.4

./configure && make && make install-full

sudo cp classification.config /etc/suricata
sudo cp reference.config /etc/suricata
sudo cp suricata.yaml /etc/suricata
