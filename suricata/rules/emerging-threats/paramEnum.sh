#!/bin/bash

param_list=(content flow distance pcre depth within flowbits isdataat fast_pattern threshold offset byte_test uricontent byte_jump dsize urilen itype icode flags stream_size byte_extract tls.fingerprint ip_proto window fragbits icmp_id ack asn1 id tag icmp_seq ssl_version detection_filter ttl ssl_state ipopts ssh.softwareversion seq fragoffset dce_iface app-layer-protocol)
proto_list=(http tcp dns tls udp ip icmp ftp smtp smb ssh)
str_to_ignore_list=(Error opening file /usr/local/var/log/suricata/suricata.log =========Supported App Layer Protocols=========)
ignore_str=0
array=()

for proto in "${proto_list[@]}";
do
    array=()
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
        for param in "${param_list[@]}";
        do            
            if [ $param != "=====Supported" ] && [ $param != "keywords=====" ] && [ $param != '-' ] && [ $param != "lua" ] && [ $param != "(not" ] && [ $param != "built-in)" ] && [ $param != "msg" ] && [ $param != "rev" ] && [ $param != "sid" ] && [ $param != "reference" ] && [ $param != "metadata" ] && [ $param != "target" ] && [ $param != "priority" ] && [ $param != "gid" ] && [ $param != "classtype" ] 
            then
                array+=("$(grep -R "alert $proto" | grep -o "\b$param:" | wc -l) $param")
                #echo $(grep -R "alert $proto" | grep -o "\b$param:" | wc -l) $param $proto >> $proto.txt
                #echo $proto
                #echo $(grep -Ro "\b$param:" | wc -l) $param
            fi
        done
        
        printf "%s\n" "${array[@]}" > param-count/$proto.txt
    fi
done