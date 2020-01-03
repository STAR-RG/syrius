#!/bin/bash

proto_list=(http ftp smtp tls ssh imap msn smb dcerpc dns enip dnp3 nfs ntp ftp-data tftp ikev2 krb5 dhcp tcp udp icmp ip modbus pkthdr ipv6)
str_to_ignore_list=(Error opening file /usr/local/var/log/suricata/suricata.log =========Supported App Layer Protocols=========)
ignore_str=0

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
        sudo echo $(find $1 -name "*.rules" -exec grep "alert $proto" {} \; | wc -l) $proto
    fi
done 
