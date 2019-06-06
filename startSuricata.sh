#!/bin/bash
sudo ldconfig /usr/local/lib
sudo suricata -c /etc/suricata/suricata.yaml -i $1
