#!/bin/bash

sudo nemesis icmp -i 8 -c 2 -S 1.2.3.4 -D 192.168.1.108 -d wlp2s0
#sudo tcpreplay --intf1=wlp2s0 ping-packet3.pcap
