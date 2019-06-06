#!/bin/bash
sudo apt-get -y install libpcre3 libpcre3-dbg libpcre3-dev \
build-essential autoconf automake libtool libpcap-dev libnet1-dev \
libyaml-0-2 libyaml-dev zlib1g zlib1g-dev libcap-ng-dev libcap-ng0 \
make libmagic-dev libjansson-dev libjansson4 pkg-config

wget http://www.openinfosecfoundation.org/download/suricata-3.1.tar.gz
tar -xvzf suricata-3.1.tar.gz
cd suricata-3.1

./configure && make && make install-full

sudo mkdir /var/log/suricata
sudo mkdir /etc/suricata

cd suricata-3.1/
sudo cp classification.config /etc/suricata
sudo cp reference.config /etc/suricata
sudo cp suricata.yaml /etc/suricata
