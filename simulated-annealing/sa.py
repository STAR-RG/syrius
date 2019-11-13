import os
import subprocess
import time
import copy
import pyshark
import random
import re
from itertools import combinations

keys_by_proto = {}
keys_by_proto["icmp"] = {"dsize":1480, "itype":255, "icode":255}#,"icmp_seq":65525, "icmp_id":65535}
keys_by_proto["tcp"] = {"window": 65525, "flags":['F', 'S', 'R', 'P', 'A', 'U', 'C', 'E', '0']}#"ack":4294967295, "seq":4294967295}
keys_by_proto["udp"] = {"fragbits": ['D', 'R', 'M']}
keys_by_proto["http"] = {}
threshold = {"type":["limit", "threshold", "both"], "track":["by_src", "by_dst"], "count": 65535, "seconds": 1}
contents = {'GET ':[], '/cron':[], '.php?include_path=':[], 'http:':[], '/':[], '/cirt':[], '.net':[], '/rfiinc':[], '.txt?? ':[], 'HTTP':[], '/1':[], 'Connection:':[], 'Keep-':[], 'User-':[], 'Agent:':[], 'Mozilla':[], '/5':[], '.00 ':[], '(Nikto':[], '/2':[], '.1':[], '.5) ':[], '(Evasions:':[], 'None) ':[], '(Test:':[], 'Host:':[], '192':[], '.168':[], '.1':[]}
#contents = {"GET ":[], "/dbmodules":[], "/DB_adodb":[], ".class":[], ".php?PHPOF_INCLUDE_PATH=":[], "http:":[], "/":[], "/cirt":[], ".net":[], "/rfiinc":[], ".txt? ":[], "HTTP":[], "/1":[], "Host:":[], "192":[], ".168":[], ".1":[], "Connection:":[], "Keep-":[], "User-":[], "Agent:":[], "Mozilla":[], "/5":[], ".00 ":[], "(Nikto":[], "/2":[], ".1":[], ".5) ":[], "(Evasions:":[], "None) ":[], "(Test:":[]}
#contents = {"GET ":[], "POST ":[], "http":[], "net":[], "HTTP":[], "1":[], "Keep-":[], "Host:":[], "eusoquerodormir":[], "Nikto":[]}
#contents = [['GET '], ['/cron'], ['.php?include_path='], ['http:'], ['/'], ['/cirt'], ['.net'], ['/rfiinc'], ['.txt?? '], ['HTTP'], ['/1'], ['Connection:'], ['Keep-'], ['User-'], ['Agent:'], ['Mozilla'], ['/5'], ['.00 '], ['(Nikto'], ['/2'], ['.1'], ['.5) '], ['(Evasions:'], ['None) '], ['(Test:'], ['Host:'], ['192'], ['.168'], ['.1']]

keyword_list=("app-layer-protocol", "uricontent", "ack", "seq", "window", "ipopts", "flags", "fragbits", "fragoffset", "ttl", "tos", "itype", "icode", "icmp_id", "icmp_seq", "dsize", "flow", "threshold", "tag", "content", "pcre", "replace", "rawbytes", "byte_test", "byte_jump", "sameip", "geoip", "ip_proto", "ftpbounce", "id", "rpc", "flowvar", "flowint", "pktvar", "flowbits", "hostbits", "ipv4-csum", "tcpv4-csum", "tcpv6-csum", "udpv4-csum", "udpv6-csum", "icmpv4-csum", "icmpv6-csum", "stream_size", "detection_filter", "decode-event", "nfq_set_mark", "bsize", "tls.version", "tls.subject", "tls.issuerdn", "tls_cert_notbefore", "tls_cert_notafter", "tls_cert_expired", "tls_cert_valid", "tls.fingerprint", "tls_store", "http_protocol", "http_start", "urilen", "http_header_names", "http_accept", "http_accept_lang", "http_accept_enc", "http_connection", "http_content_len", "http_content_type", "http_referer", "http_request_line", "http_response_line", "nfs_procedure", "nfs_version", "ssh_proto", "ssh.protoversion", "ssh_software", "ssh.softwareversion", "ssl_version", "ssl_state", "byte_extract", "file_data", "pkt_data", "app-layer-event", "dce_iface", "dce_opnum", "dce_stub_data", "smb_named_pipe", "smb_share", "asn1", "engine-event", "stream-event", "filename", "fileext", "filestore", "filemagic", "filemd5", "filesha1", "filesha256", "filesize", "l3_proto", "lua", "iprep", "dns_query", "tls_sni", "tls_cert_issuer", "tls_cert_subject", "tls_cert_serial", "tls_cert_fingerprint", "ja3_hash", "ja3_string", "modbus", "cip_service", "enip_command", "dnp3_data", "dnp3_func", "dnp3_ind", "dnp3_obj", "xbits", "base64_decode", "base64_data", "krb5_err_code", "krb5_msg_type", "krb5_cname", "krb5_sname", "template2", "ftpdata_command", "bypass", "prefilter", "compress_whitespace", "strip_whitespace", "to_sha256", "depth", "distance", "within", "offset", "nocase", "fast_pattern", "startswith", "endswith", "distance", "noalert", "http_cookie", "http_method", "http_uri", "http_raw_uri", "http_header", "http_raw_header", "http_user_agent", "http_client_body", "http_stat_code", "http_stat_msg", "http_server_body", "http_host", "http_raw_host")

default_rule_action = "alert"
default_rule_header = "any any -> any any"
default_rule_message = "msg:\"Testing rule\";"
rule_options = {}
default_rule_sid = 1

#subprocess.Popen(["sudo", "suricata", "-c", "../suricata/suricata.yaml", "-i", "wlp2s0"])

pcap = "Datasets/attack.pcap"
pkts = pyshark.FileCapture(pcap)
pkts.load_packets()
print(len(pkts._packets))
rule_protocol = str(pkts[0].highest_layer).lower()

#print(rule_protocol)

def getStats():
    rule_file = open("Datasets/all_rules.txt", "r")

    output_file_path = "data.csv"
    output_file = open(output_file_path, 'w+')

    max_content=0
    max_options=0
    rule_count = 0
    output_file.write("sid,protocol,options,contents\n")
    contents_dict={}
    rare_contents_per_rule_size = {1:{1:0}}
    max_rare_contents=0
    rare_contents_freq={}
    rules_per_size = {}
    rules_per_contents = {}
    for line in rule_file:
        if line == "\n":
            continue
        rule_size = 0
        line = line.strip()
        rare_contents_count = 0

        for keyword in keyword_list:
            keyword = ' ' + keyword + str(":")
            rule_size += line.count(keyword)

        contents = re.findall(r'content:\"(.+?)\"\;',line)

        for content in contents:
            if content in contents_dict:
                contents_dict[content] += 1
            else:
                contents_dict[content] = 1
        
        if " content:" in line:
            for content in contents:
                if contents_dict[content] < 10:
                    rare_contents_count+=1
            
            if rare_contents_count in rare_contents_freq:
                rare_contents_freq[rare_contents_count] += 1
            else:
                rare_contents_freq[rare_contents_count] = 1

            if rare_contents_count>max_rare_contents:
                max_rare_contents=rare_contents_count

        for i in range(1, 11):
            for content in contents:
                if contents_dict[content] == i:
                    if rule_size not in rare_contents_per_rule_size:
                        rare_contents_per_rule_size[rule_size] = {1:0}
                    
                    if i in rare_contents_per_rule_size[rule_size]:
                        rare_contents_per_rule_size[rule_size][i] += 1
                    else:
                        rare_contents_per_rule_size[rule_size][i] = 1

        content_count = line.count(" content:")
        #content_count += line.count(" content: ")
        proto = line.split("alert ")[1].split(' ')[0]
        sid = line.split("sid:")[1].split(";")[0]
        output_file.write(str(sid) + "," + str(proto) + "," + str(rule_size) + "," + str(content_count)+'\n')
        if content_count>max_content:
            max_content = content_count
        if rule_size>max_options:
            max_options = rule_size
        
        if content_count in rules_per_contents:
            rules_per_contents[content_count] += 1
        else:
            rules_per_contents[content_count] = 1

        if rule_size in rules_per_size:
            rules_per_size[rule_size] += 1
        else:
            rules_per_size[rule_size] = 1
        rule_count += 1

    """tmp_list = []
    for i in sorted(list(rules_per_size)):
        tmp_list.append(rules_per_size[i])

    rules_per_size = tmp_list

    tmp_list = []
    for i in sorted(list(rules_per_contents)):
        tmp_list.append(rules_per_contents[i])

    rules_per_contents = tmp_list
    """
    print(rule_count)
    print(rules_per_contents)
    print(rules_per_size)

    """x=0
    while 1:
        x=1
    """
    frequent_contents=0

    for key, value in contents_dict.items():
        if value >= 10:
            #print(key)
            frequent_contents+=1

    output_file.close()

    return rules_per_size, rules_per_contents

def ruleSizeFitness(rule):
    rules_per_size = {5: 5353, 3: 3662, 1: 1301, 6: 2911, 12: 323, 4: 3250, 7: 1337, 8: 1246, 9: 763, 10: 495, 2: 4910, 13: 463, 11: 437, 14: 266, 18: 74, 16: 162, 15: 146, 17: 81, 25: 31, 20: 61, 29: 39, 30: 29, 32: 4, 19: 68, 37: 3, 36: 30, 31: 30, 27: 24, 48: 1, 47: 1, 21: 41, 22: 35, 28: 72, 26: 9, 23: 16, 24: 25, 40: 1, 34: 44, 46: 1, 66: 1, 43: 1, 33: 43, 0: 11, 51: 1, 42: 1, 50: 1, 35: 20, 38: 8, 41: 1}

    rule_count=27833

    rule_size = 0

    for keyword in keyword_list:
        keyword = ' ' + keyword + str(":")
        rule_size += str(rule).count(keyword)
    fitness = 0
    if rule_size in rules_per_size:
        fitness = rules_per_size[rule_size]/rule_count
    else:
        fitness = 0

    return fitness

def ruleContentsFitness(rule):
    rules_per_contents = {0: 2134, 3: 5841, 5: 1622, 2: 5103, 6: 805, 1: 9164, 4: 1987, 8: 340, 7: 535, 10: 53, 11: 40, 9: 154, 12: 20, 17: 4, 13: 12, 14: 6, 16: 7, 15: 4, 22: 1, 20: 1}

    rule_count=27833

    content_count = str(rule).count(" content:")
    fitness = 0

    if content_count in rules_per_contents:
        fitness = rules_per_contents[content_count]/rule_count
    else:
        fitness = 0
    
    return fitness

def writeRuleOnFile(rules):
    ruleFile_path = "../suricata/pesquisa/individual.rules"
    open(ruleFile_path, 'w').close()
    ruleFile = open(ruleFile_path, 'w+')
    ruleFile.seek(0)
    ruleFile.truncate()
    for rule in rules:
        #print("CCCCCCCCCCCCCCCCCCCC")
        #print(str(rule))
        ruleFile.write(str(rule) + "\n" + "\n")
    ruleFile.close()
    time.sleep(0.050)

def reloadSuricataRules():
    subprocess.Popen(["sudo", "kill", "-USR2", str(getSuricataPid())])
    time.sleep(0.200)

def getSuricataPid():
    return subprocess.Popen(["pidof", "suricata"], stdout=subprocess.PIPE, encoding="utf-8").communicate()[0].rstrip()

def getLocalIp():
    return subprocess.Popen(["sh", "getLocalIp.sh"], stdout=subprocess.PIPE, encoding="utf-8").communicate()[0].rstrip()

def sendAttack():
    subprocess.Popen(["sh", "sendAttack.sh", pcap], stdout=subprocess.DEVNULL).wait()

def getRuleFitness(keywords):
    if len(keywords) <= 1:
        return 0

    if ' ' in keywords:
        keywords.remove(' ')

    for i in range(0, len(keywords)):
        keywords[i] = keywords[i].split(" ")
        while '' in keywords[i]:
            keywords[i].remove('')

        keywords[i][0] = keywords[i][0][:-1]
    
    fitness = 0
    for i in range(1, len(keywords)):
        fitness = fitness + float(keywords[i][1])
    
    if len(keywords) > 1:
        fitness = fitness/(len(keywords)-1)

    return fitness

def evalRule(rule):
    subprocess.Popen(["sudo", "rm", "../suricata/rulesFitness.txt"], stdout=subprocess.DEVNULL).wait()
    writeRuleOnFile(rule)
    #reloadSuricataRules()  
    sendAttack()
    fitnessFile_path = "../suricata/rulesFitness.txt"

    try:
        fitnessFile = open(fitnessFile_path, "r")
    except IOError:
        return 0, 0
    
    lines = fitnessFile.readlines()
    fitness = 0
    prev_fitness = 0
    prev_matches = 0
    matches = 0
    for line in lines:
        line = line.rstrip('\n')
        keywords = line.split("-")
        
        if rule.threshold == {}:
            for key in keywords:
                if "threshold" in key:
                    keywords = keywords[:-1]
                    break

        if keywords != ['']:
            prev_fitness = fitness
            prev_matches = matches
            fitness = getRuleFitness(keywords)

        if fitness == 1:
            matches += 1
    
    if rule.protocol == "udp" and "fragbits" in rule.options:
        return prev_fitness, prev_matches
    
    return fitness, matches

def sendGoodTraffic():
    subprocess.Popen(["sudo", "sh", "sendGoodTraffic.sh"], stdout=subprocess.DEVNULL).wait()

def isEmpty(fpath):
    result=False
    fpath.seek(0)
    firstchar=fpath.read(1)
    if firstchar:
        result=True
        fpath.seek(0)
        #print("capturado")
    return result

def evalContents(rule):
    fitnessFile_path = "/usr/local/var/log/suricata/fast.log"
    open(fitnessFile_path, 'w').close()
    writeRuleOnFile(rule)
    #reloadSuricataRules() 
    sendGoodTraffic()
    output= []

    for i in range(len(rule)):
        output.append(0)

    with open(fitnessFile_path, "r") as fitnessFile:
        fitnessFile = fitnessFile.readlines()
    for i in range(len(rule)):
        for lines in fitnessFile:
            s="Testing rule {}".format(i)
            if s in lines:
                output[i]=1
                #print("BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB")
                break
    #print(output)
    return output

def evalFalsePositive(rule):
    fitnessFile_path = "../suricata/rulesFitness.txt"
    subprocess.Popen(["sudo", "rm", "../suricata/rulesFitness.txt"], stdout=subprocess.DEVNULL).wait()
    writeRuleOnFile(rule)
    reloadSuricataRules() 
    sendGoodTraffic()

    try:
        fitnessFile = open(fitnessFile_path, "r")
    except IOError:
        return 0
    
    lines = fitnessFile.readlines()

    best_fitness = 0
    for line in lines:
        line = line.rstrip('\n')

        keywords = line.split("-")
        fitness = getRuleFitness(keywords)

        if fitness > best_fitness:
            best_fitness = fitness
    
    return best_fitness

class Rule:    
    def __init__(self, action, protocol, header, message, sid):
        self.protocol = protocol
        self.action = action
        self.header = header
        self.message = message
        self.sid = sid
        self.fitness = 0
        self.threshold = {}

        rule_options = {}
        for keyword in keys_by_proto[protocol]:
            self.options = {}
            if type(keys_by_proto[protocol][keyword]) == int:
                self.options[keyword] = 0
            else:                
                rule_option = keys_by_proto[protocol][keyword][0]
                message
                self.options[keyword] = rule_option 

            print(self.options)

            print(str(self))
            fitness1, _ = evalRule(self)
            fitness2, _ = evalRule(self)
            print(fitness1)
            print(fitness2)
            if fitness1 == fitness2:
                rule_options[keyword] = self.options[keyword]

        self.options = rule_options
    
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
                            str_content = str_content + ' ' + ' \"' + str(content[i]) + '\"' + ';'
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

def evolveRuleSinglePacket(rule):
    init_fitness, _ = evalRule(rule)
    print("initial fitness: " + str(init_fitness))

    prev_fitness = init_fitness
    rule_options = list(rule.options.keys())
    for keyword in rule_options:
        if type(keys_by_proto[rule.protocol][keyword]) == int:
            while rule.options[keyword] < keys_by_proto[rule.protocol][keyword]:
                rule.options[keyword] = rule.options[keyword]+1
                print(str(rule))

                new_fitness, new_matches = evalRule(rule)
                print("#1 - rule fitness: " + str(new_fitness) + " matches: " + str(new_matches))
                
                if new_fitness < 1 and new_matches > 0:
                    del rule.options[keyword]
                    break

                if new_fitness < prev_fitness:
                    rule.options[keyword] = rule.options[keyword]-1
                    break
                else:
                    prev_fitness = new_fitness
        else:
            if rule.protocol == "tcp" and keyword == "flags":
                #print("flags:")
                all_v1 = []
                for flag in keys_by_proto[rule.protocol][keyword][:-3]:
                    all_v1.append(flag)

                all_v2 = ["", ", 12"]
                prev_option = all_v1[0]
                x = 0
                for v1 in all_v1: 
                    for v2 in all_v2:
                        rule.options[keyword] = str(v1) + str(v2)
                        print("rule:" + str(rule))

                        new_fitness, new_matches = evalRule(rule)
                        print("#2 - rule fitness: " + str(new_fitness) + " matches: " + str(new_matches))
                        print()
                        
                        if new_fitness < 1 and new_matches > 0:
                            del rule.options[keyword]
                            break
                        
                        print("PREV FITNESS: " + str(prev_fitness))
                        if new_fitness < prev_fitness:
                            rule.options[keyword] = prev_option
                            x=1
                            break
                        else:
                            prev_fitness = new_fitness
                    
                        prev_option = rule.options[keyword]
                    
                    if x == 1:
                        break
            if rule.protocol == "udp" and keyword == "fragbits":
                prev_matches = 0
                prev_option = keys_by_proto[rule.protocol][keyword][0]
                for v1 in keys_by_proto[rule.protocol][keyword]:
                    rule.options[keyword] = v1
                    print("rule:" + str(rule))

                    new_fitness, new_matches = evalRule(rule)
                    print("#3 - rule fitness: " + str(new_fitness) + " matches: " + str(new_matches))

                    if new_fitness < 1 and new_matches > 0:
                        del rule.options[keyword]
                        break

                    if new_fitness < prev_fitness:
                        rule.options[keyword] = rule.options[keyword]-1
                        break
                    else:
                        prev_fitness = new_fitness

    
    print("rule return:", rule)
                            
    return rule  

def newRuleFitness(rule):
    fit1 = ruleSizeFitness(rule)
    fit2 = ruleContentsFitness(rule)
    return (fit1+fit2)


def optimizeRule(rule):
    #getStats()
    all_rule_list = []
    new_rule = copy.deepcopy(rule)
    #print("len options:", len(rule.options))
    if len(rule.options) > 1:
        for keyword in rule.options:
            if keyword != "content":
                if len(new_rule.options) == 1:
                    break
                del new_rule.options[keyword]
                print(str(new_rule))

                fitness = evalFalsePositive(new_rule)
                print("#4 - rule fitness: " + str(fitness))
                if fitness >= 1.0:
                    new_rule.options[keyword] = rule.options[keyword]
    
    if "content" in rule.options:
        new_rule = copy.deepcopy(rule)
        rule_list = [new_rule]
        aux = []
        aux2 =[]
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
                aux2.clear()
                aux.clear()
        
        #print(rule_list)

    with open("regras_output.txt", "w+") as writer:
        for x in rule_list:
            writer.write(str(x) + "\n")
    print(time.time() - start_time)

    for rule in all_rule_list:
        print(str(rule))
    print("all rule len:", len(all_rule_list))
    
    all_rule_list = sorted(all_rule_list, key=newRuleFitness)

    for rule in all_rule_list:
        print(str(rule))
    print("all rule len:", len(all_rule_list))

    for rule in rule_list:
        print(str(rule))
    print("rule list len:", len(rule_list))
    return rule_list[0]

def evolveRuleFlood(rule):
    init_fitness, matches = evalRule(rule)          
    print("initial fitness: " + str(init_fitness) + " initial matches: " + str(matches))

    new_rule = evolveRuleSinglePacket(rule)
    new_rule = optimizeRule(new_rule)

    new_rule.threshold = {"type": "threshold", "track": "by_dst", "count": 1, "seconds": 1}

    new_fitness, matches = evalRule(new_rule)
    print(str(new_rule))
    print("#5 - rule fitness: " + str(new_fitness) + " matches: " + str(matches))
    
    while 1:
        new_rule.threshold["count"] += 1
        print(str(new_rule))
        new_fitness, matches = evalRule(new_rule)
        print("#6 - rule fitness: " + str(new_fitness) + " matches: " + str(matches))

        if new_fitness == 1 and matches == 1:
            break
    
    return new_rule

init_rule = Rule(default_rule_action, "http", default_rule_header, default_rule_message, default_rule_sid)
#init_rule.threshold = {"type": "both", "track": "by_dst", "count": 1, "seconds": 1}
print("initial rule: " + str(init_rule))
final_rule = init_rule
if len(pkts._packets) > 1:
    final_rule = evolveRuleFlood(init_rule)
else:
    #final_rule = evolveRuleSinglePacket(init_rule)
    final_rule.options["content"] = contents
    print(final_rule)
    final_rule = optimizeRule(final_rule)

if final_rule.threshold != {} and final_rule.threshold["count"] == 1:
    final_rule.threshold = {} 

print("final rule: " + str(final_rule))

print()