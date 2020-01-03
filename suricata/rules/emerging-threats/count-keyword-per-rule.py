
keyword_list=("app-layer-protocol", "uricontent", "ack", "seq", "window", "ipopts", "flags", "fragbits", "fragoffset", "ttl", "tos", "itype", "icode", "icmp_id", "icmp_seq", "dsize", "flow", "threshold", "tag", "content", "pcre", "replace", "rawbytes", "byte_test", "byte_jump", "sameip", "geoip", "ip_proto", "ftpbounce", "id", "rpc", "flowvar", "flowint", "pktvar", "flowbits", "hostbits", "ipv4-csum", "tcpv4-csum", "tcpv6-csum", "udpv4-csum", "udpv6-csum", "icmpv4-csum", "icmpv6-csum", "stream_size", "detection_filter", "decode-event", "nfq_set_mark", "bsize", "tls.version", "tls.subject", "tls.issuerdn", "tls_cert_notbefore", "tls_cert_notafter", "tls_cert_expired", "tls_cert_valid", "tls.fingerprint", "tls_store", "http_protocol", "http_start", "urilen", "http_header_names", "http_accept", "http_accept_lang", "http_accept_enc", "http_connection", "http_content_len", "http_content_type", "http_referer", "http_request_line", "http_response_line", "nfs_procedure", "nfs_version", "ssh_proto", "ssh.protoversion", "ssh_software", "ssh.softwareversion", "ssl_version", "ssl_state", "byte_extract", "file_data", "pkt_data", "app-layer-event", "dce_iface", "dce_opnum", "dce_stub_data", "smb_named_pipe", "smb_share", "asn1", "engine-event", "stream-event", "filename", "fileext", "filestore", "filemagic", "filemd5", "filesha1", "filesha256", "filesize", "l3_proto", "lua", "iprep", "dns_query", "tls_sni", "tls_cert_issuer", "tls_cert_subject", "tls_cert_serial", "tls_cert_fingerprint", "ja3_hash", "ja3_string", "modbus", "cip_service", "enip_command", "dnp3_data", "dnp3_func", "dnp3_ind", "dnp3_obj", "xbits", "base64_decode", "base64_data", "krb5_err_code", "krb5_msg_type", "krb5_cname", "krb5_sname", "template2", "ftpdata_command", "bypass", "prefilter", "compress_whitespace", "strip_whitespace", "to_sha256", "depth", "distance", "within", "offset", "nocase", "fast_pattern", "startswith", "endswith", "distance", "noalert", "http_cookie", "http_method", "http_uri", "http_raw_uri", "http_header", "http_raw_header", "http_user_agent", "http_client_body", "http_stat_code", "http_stat_msg", "http_server_body", "http_host", "http_raw_host")


import re

#rule_file = open("all_rules.txt", "r")
rule_file = open("all_rules.txt", "r")
output_file_path = "data.csv"
output_file = open(output_file_path, 'w+')

max_content=0
max_options=0
total_contents = 0
rules = 0
output_file.write("sid,protocol,options,contents\n")

for line in rule_file:
    if line == "\n":
        continue
    rule_size = 0
    line = line.strip()

    for keyword in keyword_list:
        keyword = ' ' + keyword + str(":")
        rule_size += line.count(keyword)

    content_number = line.count(" content:")
    content_number += line.count(" content: ")
    total_contents += content_number
    proto = line.split("alert ")[1].split(' ')[0]
    sid = line.split("sid:")[1].split(";")[0]
    output_file.write(str(sid) + "," + str(proto) + "," + str(rule_size) + "," + str(content_number)+'\n')
    if content_number>max_content:
        max_content = content_number
    if rule_size>max_options:
        max_options = rule_size
    rules += 1

rule_file.seek(0)

contents_dict={}
for line in rule_file:
    if line == "\n":
        continue

    contents = re.findall(r'content:\"(.+?)\"\;',line)
    #print(contents)
    for content in contents:
        if content in contents_dict:
            contents_dict[content] += 1
        else:
            contents_dict[content] = 1

most_common_content = max(contents_dict, key=contents_dict.get)

print("mcc:", most_common_content, contents_dict[most_common_content])

rule_file.seek(0)
rare_contents_per_rule_size = {1:{1:0}}
for line in rule_file:
    if line == "\n":
        continue
   
    contents = re.findall(r'content:\"(.+?)\"\;',line)

    rule_size = 0
    line = line.strip()
    for keyword in keyword_list:
        keyword = ' ' + keyword + str(":")
        rule_size += line.count(keyword)
    
    #print("wtf")
    for i in range(1, 11):
        #print("i:", i)
        for content in contents:
            if contents_dict[content] == i:
                if rule_size == 2:
                    if i == 9:
                        print(content)
               #print("rare content")
                if rule_size not in rare_contents_per_rule_size:
                    rare_contents_per_rule_size[rule_size] = {1:0}
                
                if i in rare_contents_per_rule_size[rule_size]:
                    rare_contents_per_rule_size[rule_size][i] += 1
                else:
                    rare_contents_per_rule_size[rule_size][i] = 1
                    

print(rare_contents_per_rule_size)

"""print("contents:", len(contents_dict))
for i in range(0, contents_dict[most_common_content]+1):
    if list(contents_dict.values()).count(i) > 0:
        print("(" + str(i) + ',' + str(list(contents_dict.values()).count(i)) + ")", end=' ')
print()
"""

rule_file.seek(0)
max_rare_contents=0
rare_contents_freq={}
for line in rule_file:
    if line == "\n":
        continue
    if " content:" not in line:
        continue

    rare_contents_count=0

    contents = re.findall(r'content:\"(.+?)\"\;',line)
    #print(contents)
    for content in contents:
        if contents_dict[content] < 10:
            rare_contents_count+=1
    #if rare_contents_count == 0:
    #    print(line)
    if rare_contents_count in rare_contents_freq:
        rare_contents_freq[rare_contents_count] += 1
    else:
        rare_contents_freq[rare_contents_count] = 1

    if rare_contents_count>max_rare_contents:
        max_rare_contents=rare_contents_count
    
print("mrc:",max_rare_contents)

for key, value in rare_contents_freq.items():
    print("("+str(key) + "," + str(value) + str(")"), end=' ')


frequent_contents=0

for key, value in contents_dict.items():
    if value >= 10:
        #print(key)
        frequent_contents+=1

print("Frequent contents:",frequent_contents)

print()
print("Total rules:", rules)
print("Max options:", max_options)
print("Max contents:", max_content)

output_file.close()

data = open("data.csv", "r")
lines = data.read()

print("contents:", end=' ')
for i in range(0,12):
    print("("+str(i) + ',' + str(lines.count(","+str(i)+","))+")", end=' ')

print()

print("contents:", end=' ')
for i in range(0,12):
    print("("+str(i) + ',' + str(lines.count(","+str(i)+"\n"))+")", end=' ')
print()