#!/bin/bash

proto_list=($(suricata --list-app-layer-protos) tcp udp icmp ip modbus pkthdr ipv6)          
str_to_ignore_list=(Error opening file /usr/local/var/log/suricata/suricata.log =========Supported App Layer Protocols=========)
ignore_str=0

mkdir rulesWithoutContent
      
for proto in "${proto_list[@]}";                        
do      
    ignore_str=0      
      
    for str_to_ignore in "${str_to_ignore_list[@]}";      
    do      
        if [ $proto == $str_to_ignore ]              
        then      
            ignore_str=1      
            break      
        fi      
    done      
      
    if [ $ignore_str == 0 ]      
    then      
        #echo $app_layer_proto
        sudo grep -R "alert.*msg" $1 | grep -v "content" | grep "$proto " | grep -o "alert.*" > rulesWithoutContent/$proto"RulesWithoutContent.rules"
    fi      
done      
