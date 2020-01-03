#!/bin/bash

proto_list=(http tcp dns tls udp ip icmp ftp smtp smb ssh)

meta_keywords=(msg sid rev gid classtype reference priority metadata target)

keyword_list=(app-layer-protocol uricontent ack seq window ipopts flags fragbits fragoffset ttl tos itype icode icmp_id icmp_seq dsize flow threshold tag content pcre replace rawbytes byte_test byte_jump sameip geoip ip_proto ftpbounce id rpc flowvar flowint pktvar flowbits hostbits ipv4-csum tcpv4-csum tcpv6-csum udpv4-csum udpv6-csum icmpv4-csum icmpv6-csum stream_size detection_filter decode-event nfq_set_mark bsize tls.version tls.subject tls.issuerdn tls_cert_notbefore tls_cert_notafter tls_cert_expired tls_cert_valid tls.fingerprint tls_store http_protocol http_start urilen http_header_names http_accept http_accept_lang http_accept_enc http_connection http_content_len http_content_type http_referer http_request_line http_response_line nfs_procedure nfs_version ssh_proto ssh.protoversion ssh_software ssh.softwareversion ssl_version ssl_state byte_extract file_data pkt_data app-layer-event dce_iface dce_opnum dce_stub_data smb_named_pipe smb_share asn1 engine-event stream-event filename fileext filestore filemagic filemd5 filesha1 filesha256 filesize l3_proto lua iprep dns_query tls_sni tls_cert_issuer tls_cert_subject tls_cert_serial tls_cert_fingerprint ja3_hash ja3_string modbus cip_service enip_command dnp3_data dnp3_func dnp3_ind dnp3_obj xbits base64_decode base64_data krb5_err_code krb5_msg_type krb5_cname krb5_sname template2 ftpdata_command bypass prefilter compress_whitespace strip_whitespace to_sha256 depth distance within offset nocase fast_pattern startswith endswith distance noalert http_cookie http_method http_uri http_raw_uri http_header http_raw_header http_user_agent http_client_body http_stat_code http_stat_msg http_server_body http_host http_raw_host)

#modifiers_list=(depth distance within offset nocase fast_pattern startswith endswith distance noalert http_cookie http_method http_uri http_raw_uri http_header http_raw_header http_user_agent http_client_body http_stat_code http_stat_msg http_server_body http_host http_raw_host)

#keyword_list=(app-layer-protocol ack seq window ipopts flags)

for proto in "${proto_list[@]}";
do
    count=0
    for keyword in "${keyword_list[@]}";
    do
        c=$(grep -R "alert $proto" | grep "$keyword:" | wc -l)
        if [ $c != "0"  ]
        then
            #echo $keyword
            count=$(($count+1))
        fi
    done
        echo $count $proto
        #echo 
done

