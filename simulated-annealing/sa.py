import os
import subprocess
import time
import copy
import pyshark
import random
import re
import binascii
import argparse
import csv
import math
from functools import partial, reduce
from itertools import combinations

#open("bad.rules", 'w').close()
attacks_list = ["adaptor", "coldfusion", "htaccess", "idq", "issadmin", "system", "script", "pingscan", "synflood"]
parser = argparse.ArgumentParser(description="Description.")
parser.add_argument('attack', metavar='A')
args = parser.parse_args()

#ruleFile_path = "./attacks/" + str(args.attack) + ".rules"
ruleFile_path = "./attacks/" + str(args.attack) + ".rules"
fitnessFile_path = "./suricata-logs/" + str(args.attack) + ".log"

time_begin = time.time()

contents_dict = {}
contents_dict["cron"] = {'GET':[], '/cron.php?':["http_uri", "nocase"], 'include_path=':["http_uri", "nocase"], 'http:':[], '/cirt.net':[], '/rfiinc':[], '../':[], '.txt??':[], 'HTTP':[], '/1.1':[], 'Connection:':[], 'Keep-Alive':[], 'User-Agent':[], 'Mozilla':[], '5.00':[], '(Nikto':[], '/2.1.5)':[], '(Evasions:':[], 'None)':[], '(Test':[], '004603)':[], 'Host:':[], '192.168.1.108': []}

contents_dict["htaccess"] = {'GET':[], '/Ud3uMSnb':[], '.htaccess':["http_uri", "nocase"], 'HTTP':[], '/1.1':[], 'User-Agent:':[], 'Mozilla':[], '/5.00':[], '(Nikto':[], '/2.1.5)':[], '(Evasions:':[], 'None)':[], '(Test:':[], 'map_codes)':[], 'Connection:':[], 'Keep-Alive':[], 'Host:':[]}

contents_dict["jsp"] = {'GET':[], '/examples':[], '/jsp/snp/':["http_uri"], 'anything':[], '.snp':["http_uri"], 'HTTP':[], '/1.1':[], 'User-Agent:':[], 'Mozilla':[], '/5.00':[], '(Nikto':[], '/2.1.5)':[], '(Evasions:':[], 'None)':[], '(Test:':[], '001001)':[], 'Content-Length:':[], '1':[], 'Content-Type:':[], 'application':[], '/x-':[], 'www-':[], 'form-':[], 'urlencoded':[], 'Host:':[], '192.168.1.108': [], 'Connection:':[], 'Keep-Alive':[]}

contents_dict["coldfusion"] = {'GET':["http_method", "nocase"], '/CFIDE/administrator':["http_uri", "nocase"], '/index':[], '.cfm':[], 'HTTP':[], '/1.1':[], 'User-Agent:':[], 'Mozilla':[], '/5.00':[], '(Nikto':[], '/2.1.5)':[], '(Evasions:':[], 'None)':[], '(Test:':[], '003067)':[], 'Connection:':[], 'Keep-Alive':[], 'Host:':[], '192.168.1.108': []}

contents_dict["adaptor"] = {'GET':[], '/jmx-console':[], '/HtmlAdaptor':["http_uri", "nocase"], 'action=inspect':["http_uri", "nocase"], 'M':[], 'bean':["http_uri", "nocase"], 'name=':["http_uri"], 'Catalina%3Atype%3DServer':[], 'HTTP':[], '/1.1':[], 'User-Agent:':[], 'Mozilla':[], '/5.00':[], '(Nikto':[], '/2.1.5)':[], '(Evasions:':[], 'None)':[], '(Test:':[], '003846)':[], 'Connection:':[], 'Keep-Alive':[], 'Host:':[], '192.168.1.108': []}

contents_dict["script"] = {'GET':[], '/themes/mambosimple.php?':[], 'detection=':[], 'detected&sitename=':[], '</title>':[], '<script>':[], 'alert':[], '(document.cookie)':[], '</script>':["http_uri", "nocase"], 'HTTP/1.1':[], '192.168.1.108':[], 'User-Agent:':[], 'Mozilla':[], '/5.00':[], '(Nikto':[], '/2.1.5)':[],  '(Evasions:':[], 'None)':[], '(Test:':[], '000121)':[], 'Connection:':[], 'Keep-Alive':[]}

contents_dict["issadmin"] = {'GET':[], '/scripts':[], '/iisadmin':["nocase", "http_uri"], '/bdir.htr':[],  'HTTP/1.1':[], '192.168.1.108':[], 'User-Agent:':[], 'Mozilla':[], '/5.00':[], '(Nikto':[], '/2.1.5)':[],  '(Evasions:':[], 'None)':[], '(Test:':[], '000121)':[], 'Connection:':[], 'Keep-Alive':[]}

contents_dict["idq"] = {'GET':[], '/scripts':[], '/samples':[], '/search':[], '/author':[], '.idq':[], 'HTTP/1.1':[], '192.168.1.108':[], 'User-Agent:':[], 'Mozilla':[], '/5.00':[], '(Nikto':[], '/2.1.5)':[],  '(Evasions:':[], 'None)':[], '(Test:':[], '000121)':[], 'Connection:':[], 'Keep-Alive':[]}

contents_dict["system"] = {'GET':[], '/c':[], '/winnt':[], '/system32/':["http_uri", "nocase"], 'cmd.exe?':[], '/c+dir+':[], '/OG':[], 'HTTP/1.1':[], '192.168.1.108':[], 'User-Agent:':[], 'Mozilla':[], '/5.00':[], '(Nikto':[], '/2.1.5)':[],  '(Evasions:':[], 'None)':[], '(Test:':[], '000121)':[], 'Connection:':[], 'Keep-Alive':[]}

if args.attack in contents_dict:
    contents = contents_dict[args.attack]
else:
    print("ataque sem content")

keyword_list=("app-layer-protocol", "uricontent", "ack", "seq", "window", "ipopts", "flags", "fragbits", "fragoffset", "ttl", "tos", "itype", "icode", "icmp_id", "icmp_seq", "dsize", "flow", "threshold", "tag", "content", "pcre", "replace", "rawbytes", "byte_test", "byte_jump", "sameip", "geoip", "ip_proto", "ftpbounce", "id", "rpc", "flowvar", "flowint", "pktvar", "flowbits", "hostbits", "ipv4-csum", "tcpv4-csum", "tcpv6-csum", "udpv4-csum", "udpv6-csum", "icmpv4-csum", "icmpv6-csum", "stream_size", "detection_filter", "decode-event", "nfq_set_mark", "bsize", "tls.version", "tls.subject", "tls.issuerdn", "tls_cert_notbefore", "tls_cert_notafter", "tls_cert_expired", "tls_cert_valid", "tls.fingerprint", "tls_store", "http_protocol", "http_start", "urilen", "http_header_names", "http_accept", "http_accept_lang", "http_accept_enc", "http_connection", "http_content_len", "http_content_type", "http_referer", "http_request_line", "http_response_line", "nfs_procedure", "nfs_version", "ssh_proto", "ssh.protoversion", "ssh_software", "ssh.softwareversion", "ssl_version", "ssl_state", "byte_extract", "file_data", "pkt_data", "app-layer-event", "dce_iface", "dce_opnum", "dce_stub_data", "smb_named_pipe", "smb_share", "asn1", "engine-event", "stream-event", "filename", "fileext", "filestore", "filemagic", "filemd5", "filesha1", "filesha256", "filesize", "l3_proto", "lua", "iprep", "dns_query", "tls_sni", "tls_cert_issuer", "tls_cert_subject", "tls_cert_serial", "tls_cert_fingerprint", "ja3_hash", "ja3_string", "modbus", "cip_service", "enip_command", "dnp3_data", "dnp3_func", "dnp3_ind", "dnp3_obj", "xbits", "base64_decode", "base64_data", "krb5_err_code", "krb5_msg_type", "krb5_cname", "krb5_sname", "template2", "ftpdata_command", "bypass", "prefilter", "compress_whitespace", "strip_whitespace", "to_sha256", "depth", "distance", "within", "offset", "nocase", "fast_pattern", "startswith", "endswith", "distance", "noalert", "http_cookie", "http_method", "http_uri", "http_raw_uri", "http_header", "http_raw_header", "http_user_agent", "http_client_body", "http_stat_code", "http_stat_msg", "http_server_body", "http_host", "http_raw_host")

content_modifiers = ("http_uri", "http_raw_uri", "http_method", "http_request_line", "http_client_body", "http_header", "http_raw_header", "http_cookie", "http_user_agent", "http_host", "http_raw_host", "http_accept", "http_accept_lang", "http_accept_enc", "http_referer", "http_connection", "http_content_type", "http_content_len", "http_start", "http_protocol", "http_header_names", "http_stat_msg", "http_stat_code", "http_response_line", "http_server_body", "file_data")

html_modifiers = ["http_method", "http_uri", "http_user_agent", "http_protocol", "http_host", "http_connection", "http_header", "http_request_line"]

default_rule_action = "alert"
default_rule_header = "any any -> any any"
default_rule_message = "msg:\"Testing rule\";"
rule_options = {}
default_rule_sid = 1

if str(args.attack) in ["adaptor", "coldfusion", "htaccess", "cron", "jsp", "script", "issadmin", "idq", "system"]:
    pcapAttack = "Datasets/nikto-" + str(args.attack) + ".pcap"
else:
    pcapAttack = "Datasets/" + str(args.attack) + ".pcap"

if args.attack == "pingscan":
    pcapAttack = "Datasets/pingscan.pcap"

pcapVariations = "Datasets/all-" + str(args.attack) + ".pcap"
pkts = pyshark.FileCapture(pcapAttack)
pkts.load_packets()
allpkts = pyshark.FileCapture(pcapVariations)
allpkts.load_packets()
print(len(pkts._packets))
rule_protocol = str(pkts[0].highest_layer).lower()
print(rule_protocol)

def getContentsPerModifiers():
    global pcapAttack
    cap = pyshark.FileCapture(pcapAttack)
    cap.load_packets()
    pkt_content_modifiers = {}
    
    if cap[0].http.request :
        pkt_content_modifiers["http_method"] = cap[0].http.request_method
        pkt_content_modifiers["http_uri"] = cap[0].http.request_uri
        pkt_content_modifiers["http_user_agent"] = str(cap[0].http.request_line)
        pkt_content_modifiers["http_protocol"] = cap[0].http.request_version
        pkt_content_modifiers["http_host"] = "Host: " + str(cap[0].http.host)
        pkt_content_modifiers["http_connection"] = "Connection: " + str(cap[0].http.connection)
        pkt_content_modifiers["http_header"] = pkt_content_modifiers["http_host"] + ' ' + pkt_content_modifiers["http_user_agent"] + ' ' + pkt_content_modifiers["http_connection"]
        pkt_content_modifiers["http_request_line"] = cap[0].http.chat

    for c in pkt_content_modifiers:
        if "\\xd\\xa" in pkt_content_modifiers[c]:
            pkt_content_modifiers[c] = pkt_content_modifiers[c].replace("\\xd\\xa", '')
        if "\\r\\n" in pkt_content_modifiers[c]:
            pkt_content_modifiers[c] = pkt_content_modifiers[c].replace("\\r\\n", '')
    
    return pkt_content_modifiers

def getTokens():
    global pcapAttack
    cap_raw = pyshark.FileCapture(pcapAttack, include_raw=True, use_json=True)
    cap = pyshark.FileCapture(pcapAttack)
    cap.load_packets()
    aux_list = []

    for pkt in cap_raw:
        hex_data = str(binascii.b2a_hex(pkt.get_raw_packet()))[134:][:-1]
        str_data = str(binascii.unhexlify(hex_data))[2:][:-1]

        tokens = str_data.split(' ')
        
        aux_list = []
        for t in range(0, len(tokens)):
            aux = tokens[t].split('/')
            if len(aux) > 1:
                for a in range(1, len(aux)):
                    aux[a] = str('/') + aux[a]
            for a in aux:
                aux_list.append(a)

        tokens = copy.deepcopy(aux_list)
        aux_list = []
        for t in range(0, len(tokens)):
            aux = tokens[t].split('?')
                
            for a in aux:
                aux_list.append(a)
        
        tokens = copy.deepcopy(aux_list)
        aux_list = []
        for t in range(0, len(tokens)):
            aux = tokens[t].split('&')
                
            for a in aux:
                aux_list.append(a)
        
        tokens = copy.deepcopy(aux_list)
        aux_list = []
        for t in range(0, len(tokens)):
            aux = tokens[t].split(';')
            if len(aux) > 1:
                for a in range(0, len(aux)-1):
                    aux[a] = aux[a] + str(';')

            for a in aux:
                aux_list.append(a)
        
        tokens = copy.deepcopy(aux_list)
        aux_list = []
        for t in range(0, len(tokens)):
            aux = tokens[t].split(':')
            if len(aux) > 1:
                for a in range(0, len(aux)-1):
                    aux[a] = aux[a] + str(':')

            for a in aux:
                aux_list.append(a)

        tokens = copy.deepcopy(aux_list)
        aux_list = []
        for t in range(0, len(tokens)):
            aux = tokens[t].split("\\n")
            if len(aux) > 1:
                for a in range(0, len(aux)-1):
                    aux[a] = aux[a] + str("\\n")

            for a in aux:
                aux_list.append(a)

        tokens = copy.deepcopy(aux_list)
        aux_list = []
        for t in range(0, len(tokens)):
            aux = tokens[t].split('=')
            if len(aux) > 1:
                for a in range(0, len(aux)-1):
                    aux[a] = aux[a] + str('=')

            for a in aux:
                aux_list.append(a)

        while '' in aux_list:
            aux_list.remove('')
        
        while ' ' in aux_list:
            aux_list.remove(' ')
        
        tokens = copy.deepcopy(aux_list)

    tokens = {}

    for aux in aux_list:
        aux = aux.replace("\\r\\n", '')
        if aux != '':
            tokens[aux] = []

    #print(tokens)

    return tokens

def getRuleSize(rule):
    global keyword_list
    rule_size = 0

    for keyword in keyword_list:
        aux_key = ' ' + keyword + ':'
        rule_size += rule.count(aux_key)

    return rule_size

def getKeywordsFrequency():
    global keyword_list
    global content_modifiers
    keywords_freq = {}

    with open("Datasets/all_rules.txt", "r") as rule_file:
        for line in rule_file:
            if line == "\n":
                continue

            if str("alert " + rule_protocol) in line:
                line = line.strip()
                for keyword in keyword_list:
                    aux_key = ' ' + keyword + ':'
                    if keyword in keywords_freq:
                        keywords_freq[keyword] += line.count(aux_key)
                    else:
                        keywords_freq[keyword] = line.count(aux_key)
                
                for modifier in content_modifiers:
                    aux_modifier = modifier + ';'

                    if modifier in keywords_freq:
                        keywords_freq[modifier] += line.count(aux_modifier)
                    else:
                        keywords_freq[modifier] = line.count(aux_modifier)
    
    return keywords_freq

def getRulesPerSize():
    rules_per_size = {}
    with open("Datasets/all_rules.txt", "r") as rule_file:
        for line in rule_file:
            if line == "\n":
                continue
            
            
            if str("alert " + rule_protocol) in line:
                line = line.strip()
                rule_size = getRuleSize(line)

                if rule_size in rules_per_size:
                    rules_per_size[rule_size] += 1
                else:
                    rules_per_size[rule_size] = 1

    return rules_per_size
   
def getContentsDict():
    contents_dict = {}
    with open("Datasets/all_rules.txt", "r") as rule_file:
        for line in rule_file:
            if line == "\n":
                continue

            if str("alert " + rule_protocol) in line:
                line = line.strip()              
                contents = re.findall(r'content:\"(.+?)\"\;',line)

                for content in contents:
                    if content in contents_dict:
                        contents_dict[content] += 1
                    else:
                        contents_dict[content] = 1
    
    return contents_dict

def getRulesPerContents():
    rules_per_contents = {}
    with open("Datasets/all_rules.txt", "r") as rule_file:
        for line in rule_file:
            if line == "\n":
                continue

            if str("alert " + rule_protocol) in line:
                line = line.strip()
                content_count = line.count(" content:")
                
                if content_count in rules_per_contents:
                    rules_per_contents[content_count] += 1
                else:
                    rules_per_contents[content_count] = 1
    
    return rules_per_contents

def getRareContentsFreq():
    rare_contents_freq = {}
    contents_dict = getContentsDict()
    max_rare_contents = 0

    with open("Datasets/all_rules.txt", "r") as rule_file:
        for line in rule_file:
            if line == "\n":
                continue

            if str("alert " + rule_protocol) in line:
                rare_contents_count = 0
                line = line.strip()
                contents = re.findall(r'content:\"(.+?)\"\;',line)
                
                if " content:" in line:
                    for content in contents:
                        if contents_dict[content] < 10:
                            rare_contents_count += 1
                    
                    if rare_contents_count in rare_contents_freq:
                        rare_contents_freq[rare_contents_count] += 1
                    else:
                        rare_contents_freq[rare_contents_count] = 1

                    if rare_contents_count > max_rare_contents:
                        max_rare_contents = rare_contents_count

    return rare_contents_freq

def getRareContentsPerRuleSize():
    rare_contents_per_rule_size = {1:{1:0}}
    contents_dict = getContentsDict()
    
    with open("Datasets/all_rules.txt", "r") as rule_file:
        for line in rule_file:
            if line == "\n":
                continue

            if str("alert " + rule_protocol) in line:
                line = line.strip()
                rule_size = getRuleSize(line)
                contents = re.findall(r'content:\"(.+?)\"\;',line)

                for i in range(1, 11):
                    for content in contents:
                        if contents_dict[content] == i:
                            if rule_size not in rare_contents_per_rule_size:
                                rare_contents_per_rule_size[rule_size] = {1:0}
                            
                            if i in rare_contents_per_rule_size[rule_size]:
                                rare_contents_per_rule_size[rule_size][i] += 1
                            else:
                                rare_contents_per_rule_size[rule_size][i] = 1

    return rare_contents_per_rule_size

def getMaxRuleSize():
    max_rule_size = 0
    with open("Datasets/all_rules.txt", "r") as rule_file:
        for line in rule_file:
            if line == "\n":
                continue

            if str("alert " + rule_protocol) in line:
                line = line.strip()
                rule_size = getRuleSize(line)

                if rule_size>max_rule_size:
                    max_rule_size = rule_size

    return max_rule_size

def getMaxContents():
    max_contents = 0
    with open("Datasets/all_rules.txt", "r") as rule_file:
        for line in rule_file:
            if line == "\n":
                continue

            if str("alert " + rule_protocol) in line:
                line = line.strip()
                content_count = line.count(" content:")
                
                if content_count>max_contents:
                    max_contents = content_count
    
    return max_contents

def getStats():
    output_file_path = "data.csv"
    output_file = open(output_file_path, 'w+')

    with open(output_file_path, 'w+') as output_file:
        output_file.write("sid,protocol,options,contents\n")

    with open("Datasets/all_rules.txt", "r") as rule_file:
        for line in rule_file:
            if line == "\n":
                continue

            if str("alert " + rule_protocol) in line:
                line = line.strip()
                rule_size = getRuleSize(line)
                content_count = line.count(" content:")
                proto = line.split("alert ")[1].split(' ')[0]
                sid = line.split("sid:")[1].split(";")[0]
                
                with open(output_file_path, 'a') as output_file:
                    output_file.write(str(sid) + "," + str(proto) + "," + str(rule_size) + "," + str(content_count)+'\n')

    return 1

rules_per_size = getRulesPerSize()
rules_per_contents = getRulesPerContents()
contents_dict = getContentsDict()
keywords_freq = getKeywordsFrequency()
    
i=0

sd = [(k, contents_dict[k]) for k in sorted(contents_dict, key=contents_dict.get, reverse=True)]

for content in sd:
    i += 1
    print(content)
    if i == 10:
        break    


print("keyword_freq:", keywords_freq)
#exit()

html_modifiers_freq = {}
def getHtmlModifiersFreq(keywords_freq):
    global html_modifiers
    global html_modifiers_freq

    for mod in html_modifiers:
        if mod in keywords_freq:
            html_modifiers_freq[mod] = keywords_freq[mod]
    
    return html_modifiers_freq

def getLowerCaseContentsDict():
    global contents_dict
    low_case_contents_dict = {}

    for k, v in contents_dict.items():
        if k.lower() in low_case_contents_dict:
            low_case_contents_dict[k.lower()] += v
        else:
            low_case_contents_dict[k.lower()] = v
    
    return low_case_contents_dict

if rule_protocol == "http":
    pkt_content_modifiers = getContentsPerModifiers()
    html_modifiers_freq = getHtmlModifiersFreq(keywords_freq)

    print("pkt_content_modifiers", pkt_content_modifiers)
    print()
    print("html_modifiers_freq:", html_modifiers_freq)
    print()
    
    low_case_contents_dict = getLowerCaseContentsDict()

    lower_case_pkt_content_modifiers = dict((k, v.lower()) for k,v in pkt_content_modifiers.items())
    print()

max_fitness = [0,0,0,0,0]

def ruleSizeFitness(rule):
    global rules_per_size
    rule_size = 0

    for keyword in keyword_list:
        keyword = ' ' + keyword + str(":")
        rule_size += str(rule).count(keyword)

    fitness = 0

    if rule_size in rules_per_size:
        fitness = rules_per_size[rule_size]/max(rules_per_size.values())
    else:
        fitness = 0

    return fitness

def ruleContentsFitness(rule):
    global rules_per_contents
    content_count = str(rule).count(" content:")
    fitness = 0

    if content_count in rules_per_contents:
        fitness = rules_per_contents[content_count]/max(rules_per_contents.values())
    else:
        fitness = 0
    
    return fitness

def rareContentsFitness(rule):
    global contents_dict
    global low_case_contents_dict
    fitness = 0
    count = 0
    
    for content in rule.options["content"]:
        if "nocase" in rule.options["content"][content]:
            lower_content = content.lower()
            if lower_content in low_case_contents_dict:
                count += 1
                fitness += low_case_contents_dict[lower_content]/max(low_case_contents_dict.values())
        else:
            if content in contents_dict:
                count += 1
                fitness += contents_dict[content]/max(contents_dict.values())

    if count > 0:
        fitness = fitness/count
    else:
        fitness = 0

    return fitness

def ruleContentsModifiersFitness(rule):
    global keywords_freq
    global pkt_content_modifiers
    global html_modifiers_freq
    global lower_case_pkt_content_modifiers
    fitness = 0

    if "content" in rule.options:
        rule_contents = rule.options["content"]
    else:
        return fitness
    
    count = 0
    fit_aux = 0
    
    for content in rule_contents:
        count = 0
        fitness = 0
        for keyword in pkt_content_modifiers:
            if "nocase" in rule_contents[content]:
                if content.lower() in lower_case_pkt_content_modifiers[keyword]:
                    count += 1
                    fitness += keywords_freq[keyword]/max(list(html_modifiers_freq.values()))
            else:
                if content in pkt_content_modifiers[keyword]:
                    count += 1
                    fitness += keywords_freq[keyword]/max(list(html_modifiers_freq.values()))
        
        if count > 0:
            fitness = fitness/count

        fit_aux += fitness

    if count == 0:
        return 0
    
    return fit_aux/len(rule_contents)

def ruleOptionsFitness(rule):
    global keywords_freq
    count = 0
    fitness = 0

    for option in rule.options:
        count += 1
        fitness += keywords_freq[option]/max(list(keywords_freq.values()))
    
    if count > 0:
        fitness = fitness/count

    return fitness


def writeRuleOnFile(rules):
    global ruleFile_path
    open(ruleFile_path, 'w').close()
    ruleFile = open(ruleFile_path, 'w+')
    ruleFile.seek(0)
    ruleFile.truncate()
    for rule in rules:
        ruleFile.write(str(rule) + "\n")
    ruleFile.close()
    #time.sleep(0.050)

def sendGoodTraffic(attack):
    subprocess.Popen(["sh", "sendGoodTraffic.sh", attack], stdout=subprocess.DEVNULL).wait()
    #time.sleep(0.05)

def isEmpty(fpath):
    result=False
    fpath.seek(0)
    firstchar=fpath.read(1)
    if firstchar:
        result=True
        fpath.seek(0)
        #print("capturado")
    return result

def sendAttackVariation(attack):
    subprocess.Popen(["sh", "sendAttackVariation.sh", attack], stdout=subprocess.DEVNULL).wait()
    #time.sleep(0.5)

def checkFalseNegative(rules):
    global fitnessFile_path
    global args
    variation_packets = 4

    open(fitnessFile_path, 'w').close()
    writeRuleOnFile(rules)
    sendAttackVariation(args.attack)
    
    output = []

    for i in range(len(rules)):
        output.append(0)

    with open(fitnessFile_path, "r") as fitnessFile:
        fitnessFile = fitnessFile.read()
    
    for i in range(len(rules)):
        s = '[1:'+str(rules[i].sid)+':'
        if s in fitnessFile :
            output[i] = 1
            if str(rules[i].sid) == "1099019":
                print("GOLDEN RECALL:", output[i])
        #else:
            #print("fitness file count", ':'+str(rules[i].sid)+':', fitnessFile.count(str(rules[i].sid)))
            #print("False negative rule:", rules[i])
            #print(fitnessFile)

    return output

def sendTest(attack):
    subprocess.Popen(["sh", "sendTest.sh", attack], stdout=subprocess.DEVNULL).wait()
    #time.sleep(0.5)

def checkPrecision(rules):
    global fitnessFile_path
    global args
    variation_packets = 4

    open(fitnessFile_path, 'w').close()
    writeRuleOnFile(rules)
    sendTest(args.attack)
    
    output = []

    for i in range(len(rules)):
        output.append(0)

    with open(fitnessFile_path, "r") as fitnessFile:
        fitnessFile = fitnessFile.read()
    
    for i in range(len(rules)):
        s = '[1:'+str(rules[i].sid)+':'
        if s in fitnessFile:
            output[i] = 1
        #else:
            #print("fitness file count", ':'+str(rules[i].sid)+':', fitnessFile.count(str(rules[i].sid)))
            #print("False negative rule:", rules[i])
            #print(fitnessFile)

    return output

def evalContents(rules):
    global fitnessFile_path
    global args
    open(fitnessFile_path, 'w').close()
    writeRuleOnFile(rules)
    #reloadSuricataRules() 
    sendGoodTraffic(args.attack)
    output= []

    for i in range(len(rules)):
        output.append(0)

    with open(fitnessFile_path, "r") as fitnessFile:
        fitnessFile = fitnessFile.read()
    
    if len(fitnessFile) == 0 :
        return output

    for i in range(len(rules)):
        s="Testing rule {} ".format(i)
        if s in fitnessFile:
            output[i]=1

    #print(output)
    return output

class Rule:    
    def __init__(self, action, protocol, header, message, sid):
        self.protocol = protocol
        self.action = action
        self.header = header
        self.message = message
        self.sid = sid
        self.threshold = {}
        self.fitness = []
        self.options = {}
    
    def __str__(self):
        str_options = ""
        for option in self.options:
            if option == "content":
                contents = self.options[option]
                str_content = ""
                for content in contents:
                    str_content = str_content + ' ' + str(option) + ':' + ' \"' + str(content) + '\"' + ';'
                    if len(contents[content]) > 0:
                        for i in range(0, len(contents[content])):
                            str_content = str_content + ' ' + str(contents[content][i]) + ';'
                str_options = str_options + ' ' + str_content
            else:
                str_options = str_options + ' ' + str(option) + ':' + str(self.options[option]) + ';'

        if self.threshold != {}:
            str_options = str_options + ' ' + "threshold:"
            for option in self.threshold:
                str_options = str_options + ' ' + str(option) + ' ' + str(self.threshold[option]) + ','
            str_options = str_options[:-1] + ';'
        str_options = str_options + ' ' + "sid:" + str(self.sid) + ';'
        
        str_protocol = str(self.protocol)
        if str_protocol == "http":
            str_protocol = "tcp"

        return (str(self.action) + ' ' + str(str_protocol) + ' ' + str(self.header) + ' ' + '(' + str(self.message) + str_options + ')')

    def calculateFitness(self):
        global max_fitness
        self.fitness = []
        self.fitness.append(ruleSizeFitness(self))
        self.fitness.append(ruleOptionsFitness(self))
        
        if self.protocol == "http":
            self.fitness.append(ruleContentsFitness(self))
            self.fitness.append(rareContentsFitness(self))
            self.fitness.append(ruleContentsModifiersFitness(self))
        

        for i in range(0, len(self.fitness)):
            if self.fitness[i] > max_fitness[i]:
                max_fitness[i] = self.fitness[i]
    
    def getFitness(self, weights):
        ret = 0 
        for i in range(0, len(self.fitness)):
            ret += weights[i] * self.fitness[i]
        
        ret = ret/len(self.fitness)
        
        return ret
    def getAllAttributesRaw(self):
        return (str(self.protocol) + '#' + str(self.action) + '#' + str(self.header) + '#' + str(self.message) + '#' + str(self.sid) + '#' + str(self.fitness) + '#' + str(self.threshold) + '#' + str(self.options))

def callGetFitness(rule, weights):
    return rule.getFitness(weights)

def sortRules():
    with open("all_rules_raw_"+str(args.attack)+".out", "r") as all_rules:
        all_rules = all_rules.readlines()

    all_rules_list = []
    tmp_str_rule = ""
    tmp_rule = Rule("","","","","")
    golden_rule_pos = 0

    for i in range(0, len(all_rules)):
        tmp_rule = Rule("","","","","")
        tmp_str_rule = all_rules[i].split('#')
        tmp_rule.protocol = tmp_str_rule[0]
        tmp_rule.action = tmp_str_rule[1]
        tmp_rule.header = tmp_str_rule[2]
        tmp_rule.message = tmp_str_rule[3]
        tmp_rule.sid = int(tmp_str_rule[4])
        tmp_rule.fitness = eval(tmp_str_rule[5])
        tmp_rule.threshold = eval(tmp_str_rule[6])
        tmp_rule.options = eval(tmp_str_rule[7])

        all_rules_list.append(tmp_rule)

    """print("regra 0:", str(all_rules_list[0]))
    print("fit 0:", str(all_rules_list[0].getFitness([1,1])))
    print("regra 1000:", str(all_rules_list[1000]))
    print("fit 1000:", str(all_rules_list[1000].getFitness([1,1])))



    exit()
"""
    current_pos = 0
    best_pos = math.inf
    best_rule_list = []
    best_weights = []
    all_rules_len = len(all_rules_list)
    w = []

    print("all rules len:", all_rules_len)
    
    for w0 in [0, 0.25, 0.5, 0.75, 1]:
        #w.append(w0)
        for w1 in [0, 0.25, 0.5, 0.75, 1]:
            #w.append(w1)
            for w2 in [0, 0.25, 0.5, 0.75, 1]:
                #w.append(w2)
                for w3 in [0, 0.25, 0.5, 0.75, 1]:
                    #w.append(w3)
                    for w4 in [0, 0.25, 0.5, 0.75, 1]:
                        #w.append(w4)
                        w = [w0,w1,w2,w3,w4]
                        if w != [0,0,0,0]:
                            print("weights:", str(w))
                            all_rules_list = sorted(all_rules_list, key=partial(callGetFitness, weights=w))
                            #exit()
                            for x, rule in enumerate(all_rules_list):
                                if rule.sid == 1099019:
                                    golden_rule_pos = all_rules_list.index(rule)
                                else:
                                    rule.sid=x+1

                            current_pos = all_rules_len-golden_rule_pos
                            
                            print(current_pos)

                            if current_pos <= best_pos:
                                best_pos = current_pos
                                best_rule_list = copy.deepcopy(all_rules_list)
                                best_weights = copy.deepcopy(w)
                    #w.pop()
                #w.pop()
           # w.pop()
        #w.pop()
    
    """i = 0
    for rule in best_rule_list:
        i += 1
        if "1099019" in str(rule):
            golden_index = i
            print("golden index: ", end=' ')
        print(i, " ", str(rule))
    """

    return best_rule_list, best_weights, best_pos

def sortMultipleAttacks():
    all_rules = []
    for atk in attacks_list:
        file_nme = "all_rules_raw_"+str(atk)+".out"
        try:
            with open(file_name, "r") as reader:
                #all_rules.append([])
                all_rules.append(reader.readlines())
                print(file_name, "successfully loaded.")
        except:
            print(file_name, "loading failed.")
            if i == 0:
                print("No file was loaded, something is wrong.")
                exit()
            break
 

    all_rules_list = []
    tmp_str_rule = ""
    tmp_rule = Rule("","","","","")
    golden_rule_pos = []
    current_pos = []
    best_pos = []
    best_rule_list = []
    best_weights = []

    for i in range(0, len(all_rules)):
        all_rules_list.append([])
        golden_rule_pos.append(0)
        current_pos.append(0)
        best_pos.append(math.inf)
        best_rule_list.append([])
        best_weights.append([])

        for elem in all_rules[i]:
            tmp_rule = Rule("","","","","")
            tmp_str_rule = elem.split('#')
            tmp_rule.protocol = tmp_str_rule[0]
            tmp_rule.action = tmp_str_rule[1]
            tmp_rule.header = tmp_str_rule[2]
            tmp_rule.message = tmp_str_rule[3]
            tmp_rule.sid = int(tmp_str_rule[4])
            tmp_rule.fitness = eval(tmp_str_rule[5])
            tmp_rule.threshold = eval(tmp_str_rule[6])
            tmp_rule.options = eval(tmp_str_rule[7])

            all_rules_list[i].append(tmp_rule)
    
    print("all rules list len:", len(all_rules_list))

    #exit()

    all_rules_len = []
    all_pos_sum = 0
    best_all_pos_sum = math.inf
    best_all_weights = []
    
    for elem in all_rules_list:
        all_rules_len.append(len(elem))

    print("all rules len:", all_rules_len)

    

    for w0 in [0.01, 0.25, 0.5, 0.75, 1]:
        for w1 in [0.01, 0.25, 0.5, 0.75, 1]:
            for w2 in [0.01, 0.25, 0.5, 0.75, 1]:
                for w3 in [0.01, 0.25, 0.5, 0.75, 1]:
                    for w4 in [0.01, 0.25, 0.5, 0.75, 1]:
                        all_pos_sum = 0
                        w = [w0,w1,w2,w3,w4]
                        print("weights:", str(w))
                        i=0
                        for elem in all_rules:
                            all_rules_list[i] = sorted(all_rules_list[i], key=partial(callGetFitness, weights=w))

                            for x, rule in enumerate(all_rules_list[i]):
                                if rule.sid == 1099019:
                                    golden_rule_pos[i] = all_rules_list[i].index(rule)
                                else:
                                    rule.sid=x+1

                            current_pos[i] = all_rules_len[i]-golden_rule_pos[i]
                            all_pos_sum += current_pos[i]
                            print("current pos", i, ":", current_pos[i])
                            print("best pos:", best_pos[i])
                            
                            if current_pos[i] <= best_pos[i]:
                                best_pos[i] = current_pos[i]
                                #best_rule_list[i] = copy.deepcopy(all_rules_list[i])
                                best_weights[i] = w
                            
                            i += 1
                        
                        #print("all pos sum:", all_pos_sum)
                        if all_pos_sum <= best_all_pos_sum:
                            best_all_pos_sum = all_pos_sum
                            best_all_weights = w
                    
    print("best pos:", best_pos)
    print("best weights indiv:", best_weights)
    print("best all:", best_all_pos_sum)
    print("best all weights:", best_all_weights)
    
    i = 0
    for rule in best_rule_list:
        i += 1
        if "1099019" in str(rule):
            golden_index = i
            print("golden index: ", golden_index, end=' ')
        #print(i, " ", str(rule))

    return best_rule_list, best_weights, best_pos

def optimizeRule(rule):
    all_rule_list = []
    new_rule = copy.deepcopy(rule)
    #print("len options:", len(rule.options))
    if len(rule.options) > 1:
        print("aqe")
        new_rule = copy.deepcopy(rule)
        rule_list = [new_rule]
        aux = []
        aux2 = []
        aux3 = []
        timeout = 6000
        start_time = time.time()   #inicia contador do timeout
        while time.time() - start_time < timeout:
            if not rule_list:
                break

            counter = 0
            print("RULE LIST:", len(rule_list))

            for rule in rule_list:
                if len(rule.options) == 1:
                    if len(rule_list) == 1:
                        break
                    else:
                        continue
                
                tam = 2

                if len(rule.options) == 2:
                    tam = 1

                elem = random.sample(list(rule.options.keys()), tam)
                print('RANDOM ELEM:', str(elem))
                while 1:
                    if "content" in elem:
                        elem = random.sample(list(rule.options), tam)
                    else:
                        break

                for i in range(tam):
                    new_sid=0
                    checker=False
                    tmp = copy.deepcopy(rule)
                    del tmp.options[elem[i]]
                    
                    for op in tmp.options:
                        for c in op:
                            new_sid += int(ord(c))

                    tmp.message = "msg:\"Testing rule {}\";".format(counter)
                    
                    if new_sid>0:
                        tmp.sid=new_sid
                    else:
                        tmp.sid=counter+1

                    if not aux:
                        aux.append(tmp)
                        counter+=1
                    else:
                        for z in aux:
                            if z.sid==new_sid:
                                checker=True
                                break
                            else:
                                checker=False
                        if not checker:       
                            aux.append(tmp)
                            #print("REGRA UNICA")
                            counter+=1

                    #print(tmp)
            
            for a in aux:
                print(a)
            print("len aux1:", len(aux))

            fitness_list = evalContents(aux)
            print(fitness_list)
            #print("aqui auqi auiq")

            #rule_list.clear()
            for i, fitness in enumerate(fitness_list):
                if fitness < 1.0:
                    aux2.append(aux[i])
                    #print("{} : {}".format(aux[i], fitness))
                    all_rule_list.append(aux[i])
            
            for a in aux2:
                print(a)
            print("len aux2:", len(aux2))

            if not aux2:
                #print(rule_list)
                break
            else:
                rule_list.clear()
                rule_list=aux2.copy()
                fitness_list.clear()
                aux2.clear()
                aux.clear()
    
    if "content" in rule.options:
        new_rule = copy.deepcopy(rule)
        rule_list = [new_rule]
        aux = []
        aux2 = []
        aux3 = []
        timeout = 6000
        start_time = time.time()   #inicia contador do timeout

        while time.time() - start_time < timeout:

            if not rule_list:
                break
            
            counter=0
            for rules in rule_list:
                tam=2

                if len(list(rules.options["content"].keys())) == 1:
                    tam=1
                try:
                    elem = random.sample(list(rules.options["content"].keys()),tam)
                except:
                    print("len:", len(list(rules.options["content"].keys())))
                    print("tam:", tam)

                for i in range(tam):
                    new_sid=0
                    checker=False
                    temp = copy.deepcopy(rules)
                    del temp.options["content"][elem[i]]

                    for z in temp.options["content"]:
                        for g in z:
                            new_sid+=int(ord(g))

                    temp.message = "msg:\"Testing rule {}\";".format(counter)
                    if new_sid>0:
                        temp.sid=new_sid
                    else:
                        temp.sid=counter+1
                    if not aux:
                        aux.append(temp)
                        #print("AAAAAAAA:")
                        counter+=1
                    else:
                        for z in aux:
                            if z.sid==new_sid:
                                checker=True
                                break
                            else:
                                checker=False
                        if not checker:       
                            aux.append(temp)
                            #print("REGRA UNICA")
                            counter+=1
            print(len(aux))
            #all_bad_rules_list = checkFalseNegative(aux)
            #bad_rule_list = []
            #for i, fitness in enumerate(all_bad_rules_list):
            #    if fitness == 0:
            #        aux3.append(aux[i])
            #        #print("{} : {}".format(aux[i], fitness))
            #        bad_rule_list.append(aux[i])
            #
            #with open("bad.rules", "a+") as writer:
            #    for x in bad_rule_list:
            #        writer.write(str(x) + "\n")

            fitness_list = evalContents(aux)
            #print("aqui auqi auiq")

            #rule_list.clear()
            for i, fitness in enumerate(fitness_list):
                if fitness < 1.0:
                    aux2.append(aux[i])
                    #print("{} : {}".format(aux[i], fitness))
                    all_rule_list.append(aux[i])

            if not aux2:
                #print(rule_list)
                break
            else:
                rule_list.clear()
                rule_list=aux2.copy()
                fitness_list.clear()
                aux2.clear()
                aux.clear()
        
        #print(rule_list)

    with open("regras_output.txt", "w+") as writer:
        for x in rule_list:
            writer.write(str(x) + "\n")
    print(time.time() - start_time)

    """for rule in all_rule_list:
        print(str(rule))
    print("all rule len:", len(all_rule_list))
    """
    golden_rule = copy.deepcopy(all_rule_list[0])
    golden_rule.sid= 1099019
    golden_content = {}
    golden_content["cron"] = {'GET':[], '/cron.php?':["http_uri", "nocase"], 'include_path=':["http_uri", "nocase"], '../':[]} # cron.php
    golden_content["htaccess"] = {'.htaccess':["nocase", "http_uri"]}
    golden_content["jsp"] = {'/jsp/snp/':["http_uri"], '.snp':["http_uri"]}
    golden_content["coldfusion"] = {'GET':["http_method", "nocase"], '/CFIDE/administrator':["http_uri", "nocase"]}
    golden_content["adaptor"] = {'/HtmlAdaptor':["nocase", "http_uri"], 'action=inspect':["nocase", "http_uri"], 'bean':["nocase", "http_uri"], 'name=':["http_uri"]}
    golden_content["script"] = {'</script>':["http_uri", "nocase"]}
    golden_content["issadmin"] = {'/iisadmin':["nocase"]}
    golden_content["idq"] = {'.idq':["nocase"]}
    golden_content["system"] = {'/system32/':["http_uri", "nocase"]}

    if rule_protocol == "http":
        golden_rule.options["content"] = golden_content[args.attack]
    elif rule_protocol == "icmp":
        golden_rule.options = {'dsize':0, 'itype':8}
    
    print("golden_rule:", golden_rule)
    #print("fit1: ", ruleSizeFitness(golden_rule), "fit2: ", ruleContentsFitness(golden_rule), "fit3: ", rareContentsFitness(golden_rule), "fit4: ", ruleContentsModifiersFitness(golden_rule))
    all_rule_list.append(golden_rule)
    all_rule_list.append(final_rule)
    golden_rule_pos = 0

    for i in range(0, len(all_rule_list)):
        all_rule_list[i].calculateFitness()

    with open("all_rules.out", "w+") as writer, open("all_rules_raw_"+str(args.attack)+".out", "w+") as raw_writer:
        for i in range(0, len(all_rule_list)):
            writer.write(str(all_rule_list[i])+'\n')
            raw_writer.write(str(all_rule_list[i].getAllAttributesRaw())+'\n')

    all_rule_list, best_weights, best_pos = sortRules()

    print("Best Weights:", str(best_weights))
    print("Best Pos: " + str(best_pos) + ',' + str(len(all_rule_list)))

    regrafit=[]

    print("pegando precision")
    precision=checkPrecision(all_rule_list)
    print("pegando recall")
    recall=checkFalseNegative(all_rule_list)
    i=0
    golden_index = 0

    """for rule in all_rule_list:
        if "1099019" in str(rule):
            golden_index = i
            print("golden index: ", end=' ')
        print(i, " ", str(rule))
        i += 1

    print('recall golden rule:', recall[golden_index])

    print("tamanho da variacao: {}".format(len(allpkts)))
    """

    with open("result_"+str(args.attack)+".csv", "w+", newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Rule", "Recall", "Precision", "F1 Score"])
        for (x, y, z) in zip(all_rule_list, recall, precision):
            y=y*(100/3)
            z=100-(z/20)
            f1=2*(((z*y)/100)/((y/100)+(z/100)))
            total="{} -> recall: {}%, precision: {}%\n".format(str(x), str(y), str(z))
            writer.writerow([str(x), "{}%".format(str(y)), "{}%".format(str(z)), "{}%".format(str(f1))])

    with open("result_final_"+str(args.attack)+".csv", "w+", newline='') as file:
        with open("fitness_list_"+str(args.attack)+".csv", "w+", newline='') as fitness_file:
            with open("all_rules_raw_"+str(args.attack)+".out", "w+") as raw_writer:
                writer = csv.writer(file)
                writer.writerow(["Rule", "Recall", "Precision", "F1 Score"])
                fitness_writer = csv.writer(fitness_file)
                fitness_writer.writerow(["Rule", "Fitness1", "Fitness2", "Fitness3", "Fitness4"])

                for (x, y, z) in zip(list(reversed(all_rule_list)), list(reversed(recall)), list(reversed(precision))):
                    y=y*(100/3)
                    z=100-(z/20)
                    f1=2*(((z*y)/100)/((y/100)+(z/100)))
                    if x.sid == "1099019":
                        print("GOLDEN RULE IS HERE")
                    if f1>90.0:
                        raw_writer.write(str(x.getAllAttributesRaw())+'\n')
                        total="{} -> recall: {}%, precision: {}%\n".format(str(x), str(y), str(z))
                        writer.writerow([str(x), "{}%".format(str(y)), "{}%".format(str(z)), "{}%".format(str(f1))])
                        #fitness_writer.writerow([str(x), ruleSizeFitness(x),ruleContentsFitness(x), rareContentsFitness(x),ruleContentsModifiersFitness(x)])
                        #regrafit.append((x, ruleSizeFitness(x),ruleContentsFitness(x), rareContentsFitness(x),ruleContentsModifiersFitness(x)))
                        fitness_writer.writerow([str(x), ruleSizeFitness(x), ruleOptionsFitness(x)])
                        regrafit.append((x, ruleSizeFitness(x), ruleOptionsFitness(x)))
    

    w = [1,1,1,1,1]
    print("weights:", str(w))
    normal_rules_list = sorted(all_rule_list, key=partial(callGetFitness, weights=w))

    for x, rule in enumerate(normal_rules_list):
        if rule.sid == 1099019:
            golden_rule_pos = normal_rules_list.index(rule)
        else:
            rule.sid=x+1
        #print(str(rule))

    current_pos = len(normal_rules_list) - golden_rule_pos

    print("normal pos:", current_pos)

    print("pegando precision")
    normal_precision=checkPrecision(normal_rules_list)
    print("pegando recall")
    normal_recall=checkFalseNegative(normal_rules_list)

    with open("result_"+str(args.attack)+"2.csv", "w+", newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Rule", "Recall", "Precision", "F1 Score"])
        for (x, y, z) in zip(normal_rules_list, normal_recall, normal_precision):
            y=y*(100/3)
            z=100-(z/20)
            f1=2*(((z*y)/100)/((y/100)+(z/100)))
            total="{} -> recall: {}%, precision: {}%\n".format(str(x), str(y), str(z))
            writer.writerow([str(x), "{}%".format(str(y)), "{}%".format(str(z)), "{}%".format(str(f1))])

    with open("result_final_"+str(args.attack)+"2.csv", "w+", newline='') as file:
        with open("fitness_list_"+str(args.attack)+".csv", "w+", newline='') as fitness_file:
            writer = csv.writer(file)
            writer.writerow(["Rule", "Recall", "Precision", "F1 Score"])
            fitness_writer = csv.writer(fitness_file)
            fitness_writer.writerow(["Rule", "Fitness1", "Fitness2", "Fitness3", "Fitness4"])

            for (x, y, z) in zip(list(reversed(normal_rules_list)), list(reversed(normal_recall)), list(reversed(normal_precision))):
                y=y*(100/3)
                z=100-(z/20)
                f1=2*(((z*y)/100)/((y/100)+(z/100)))
                if f1>90.0: 
                    total="{} -> recall: {}%, precision: {}%\n".format(str(x), str(y), str(z))
                    writer.writerow([str(x), "{}%".format(str(y)), "{}%".format(str(z)), "{}%".format(str(f1))])
                    #fitness_writer.writerow([str(x), ruleSizeFitness(x),ruleContentsFitness(x), rareContentsFitness(x),ruleContentsModifiersFitness(x)])
                    #regrafit.append((x, ruleSizeFitness(x),ruleContentsFitness(x), rareContentsFitness(x),ruleContentsModifiersFitness(x)))
                    fitness_writer.writerow([str(x), ruleSizeFitness(x), ruleOptionsFitness(x)])
                    regrafit.append((x, ruleSizeFitness(x), ruleOptionsFitness(x)))
            
    #with open("raw_recall.txt", "w+") as writer:
    #    for x in recall:
    #        writer.write("{}\n".format(x*25))

    #with open("raw_precision.txt", "w+") as writer:
    #    for x in precision:
    #        writer.write("{}\n".format(100-(x/20)))

    #with open("raw_f1.txt", "w+") as writer:
    #    for x, y in zip(recall, precision):
    #        x=x*25
    #        y=100-(z/20)
    #        writer.write("{}\n".format(2*(((x*y)/100)/((x/100)+(y/100)))))

    #with open("output_sorted.txt", "w+") as writer:
    #    for x in all_rule_list:
    #        writer.write(str(x) + "\n")


    return rule_list[0]

#sortMultipleAttacks()
#exit()

init_rule = Rule(default_rule_action, rule_protocol, default_rule_header, default_rule_message, default_rule_sid)

"""golden_content = {}
golden_content["adaptor"] = {'/HtmlAdaptor':["nocase", "http_uri"], 'action=inspect':["nocase", "http_uri"], 'bean':["nocase", "http_uri"], 'name=':["http_uri"]}
init_rule.options["content"] = golden_content["adaptor"]
print(ruleContentsModifiersFitness(init_rule))
exit()
"""

#print("initial rule: " + str(init_rule))
final_rule = init_rule
if len(pkts._packets) > 1:
    synflood_options = {'window':512, 'flags':'S'}
    final_rule.options = synflood_options
    final_rule.threshold = {'type':'both', 'track':'by_dst', 'count':len(pkts._packets), 'seconds': 5}
    print(final_rule)

    final_rule = optimizeRule(final_rule)
    #final_rule = evolveRuleFlood(init_rule)
else:
    #pingscan_options = {'dsize':0, 'itype':8, 'icode': 0, 'icmp_id':23570, 'icmp_seq': 3439}
    #final_rule.options = pingscan_options
    #final_rule.options["content"] = {'get':["http_method", "nocase"], '/CfiDE/administrator':["http_uri", "nocase"]}
    #final_rule.options["content"] = contents
    
    """w = [1,1,1,1]
    final_rule.calculateFitness()
    print(final_rule.getFitness(w))
    print(newRuleFitness(final_rule,w))
    print(callGetFitness(final_rule, [0.5,0.5,0.5,0.5]))
    exit()
    """

    if rule_protocol == "http":
        final_rule.options["content"] = contents
    elif rule_protocol == "icmp":
        pingscan_options = {'dsize':0, 'itype':8, 'icode':0, 'icmp_id':23570, 'icmp_seq':3439}
        final_rule.options = pingscan_options
        
    print(final_rule)
    #print("fit1: ", ruleSizeFitness(final_rule), "fit2: ", ruleContentsFitness(final_rule), "fit3: ", rareContentsFitness(final_rule), "fit4: ", #ruleContentsModifiersFitness(final_rule))
    #quit()
    final_rule = optimizeRule(final_rule)

if final_rule.threshold != {} and final_rule.threshold["count"] == 1:
    final_rule.threshold = {} 

time_end = time.time()

print("max fits:")
print(max_fitness)

print("Exec time:", time_end - time_begin)