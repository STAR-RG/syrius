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
import ast
import ctypes
from functools import partial

from copy import deepcopy

attacks_list = ["adaptor", "coldfusion", "htaccess", "idq", "issadmin", "system", "script", "synflood", "pingscan", "cron", "teardrop", "blacknurse", "inc", "jsp"]

http_attacks = ["adaptor", "coldfusion", "htaccess", "idq", "issadmin", "system", "script", "cron", "jsp", "inc", "wordpress", "sanny"]
parser = argparse.ArgumentParser(description="Description.")
parser.add_argument('attack', metavar='A')
args = parser.parse_args()

ruleFile_path = "./attacks/" + str(args.attack) + ".rules"
log_file_path = "./suricata-logs/" + str(args.attack) + ".log"

time_begin = time.time()

contents_dict = {}
contents_dict["cron"] = {'GET': [], '/cron.php?': ["http_uri", "nocase"], 'include_path=': ["http_uri", "nocase"], 'http:': [], '/cirt.net': [], '/rfiinc': [], '.txt??': [], 'HTTP': [], '/1.1': [], 'Connection:': [], 'Keep-Alive': [], 'User-Agent': [], 'Mozilla': [], '5.00': [], '(Nikto': [], '/2.1.5)': [], '(Evasions:': [], 'None)': [], '(Test': [], '004603)': [], 'Host:': [], '192.168.1.108': []}

contents_dict["htaccess"] = {'GET': [], '/Ud3uMSnb': [], '.htaccess': ["http_uri", "nocase"], 'HTTP': [], '/1.1': [], 'User-Agent:': [], 'Mozilla': [], '/5.00': [], '(Nikto': [], '/2.1.5)': [], '(Evasions:': [], 'None)': [], '(Test:': [], 'map_codes)': [], 'Connection:': [], 'Keep-Alive': [], 'Host:': []}

contents_dict["jsp"] = {'Keep-Alive': [], '/x-www-form-urlencoded': [], '(Nikto': [], '/2.1.5)': [], 'Mozilla': [], 'None)': [], 'User-Agent:': [], '001001)': [], 'Host:': [], '(Test:': [], '/jsp/snp': ["http_uri"], '/anything': [], '.snp': ["http_uri"], '(Evasions:': [], 'Content-Type:': [], '192.168.1.108': [], 'application': [], '/examples': [], 'HTTP/1.1': [], 'Content-Length:': [], '/5.00': [], '1': [], 'Connection:': [], 'GET': []}

contents_dict["coldfusion"] = {'GET': ["http_method", "nocase"], '/CFIDE/administrator': ["http_uri", "nocase"], '/index': [], '.cfm': [], 'HTTP': [], '/1.1': [], 'User-Agent:': [], 'Mozilla': [], '/5.00': [], '(Nikto': [], '/2.1.5)': [], '(Evasions:': [], 'None)': [], '(Test:': [], '003067)': [], 'Connection:': [], 'Keep-Alive': [], 'Host:': [], '192.168.1.108': []}

contents_dict["adaptor"] = {'GET': [], '/jmx-console': [], '/HtmlAdaptor': ["http_uri", "nocase"], 'action=inspect': ["http_uri", "nocase"], 'M': [], 'bean': ["http_uri", "nocase"], 'name=': ["http_uri"], 'Catalina%3Atype%3DServer': [], 'HTTP': [], '/1.1': [], 'User-Agent:': [], 'Mozilla': [], '/5.00': [], '(Nikto': [], '/2.1.5)': [], '(Evasions:': [], 'None)': [], '(Test:': [], '003846)': [], 'Connection:': [], 'Keep-Alive': [], 'Host:': [], '192.168.1.108': []}

contents_dict["script"] = {'GET': [], '/themes/mambosimple.php?': [], 'detection=': [], 'detected&sitename=': [], '</title>': [], '<script>': [], 'alert': [], '(document.cookie)': [], '</script>': ["http_uri", "nocase"], 'HTTP/1.1': [], '192.168.1.108': [], 'User-Agent:': [], 'Mozilla': [], '/5.00': [], '(Nikto': [], '/2.1.5)': [],  '(Evasions:': [], 'None)': [], '(Test:': [], '000121)': [], 'Connection:': [], 'Keep-Alive': []}

contents_dict["issadmin"] = {'GET': [], '/scripts': [], '/iisadmin': ["nocase", "http_uri"], '/bdir.htr': [],  'HTTP/1.1': [], '192.168.1.108': [], 'User-Agent:': [], 'Mozilla': [], '/5.00': [], '(Nikto': [], '/2.1.5)': [],  '(Evasions:': [], 'None)': [], '(Test:': [], '000121)': [], 'Connection:': [], 'Keep-Alive': []}

contents_dict["idq"] = {'GET': [], '/scripts': [], '/samples': [], '/search': [], '/author': [], '.idq': ["http_uri", "nocase"], 'HTTP/1.1': [], '192.168.1.108': [], 'User-Agent:': [], 'Mozilla': [], '/5.00': [], '(Nikto': [], '/2.1.5)': [],  '(Evasions:': [], 'None)': [], '(Test:': [], '000121)': [], 'Connection:': [], 'Keep-Alive': []}

contents_dict["system"] = {'GET': [], '/c': [], '/winnt': [], '/system32/': ["http_uri", "nocase"], 'cmd.exe?': [], '/c+dir+': [], '/OG': [], 'HTTP/1.1': [], '192.168.1.108': [], 'User-Agent:': [], 'Mozilla': [], '/5.00': [], '(Nikto': [], '/2.1.5)': [],  '(Evasions:': [], 'None)': [], '(Test:': [], '000121)': [], 'Connection:': [], 'Keep-Alive': []}

contents_dict["wordpress"] = {'POST': [], 'deflate': [], 'Hungry4Apples%21': [], '&pwd=': ["http_client_body"], '58.0)': [], '10.47.26.186': [], 'Gecko': [], 'Win64': [], 'log=': ["http_client_body"], 'application': [], '1': [], '/x-www-form-urlencoded': [], 'Accept-Language:': [], '&wp-submit=': ["http_client_body"], 'Firefox': [], '0.9,*': [], 'WP+Cookie+check': [], 'admin': [], '%2Fwordpress%2Fwp-admin%2F': [], 'testcookie=': [], '/html,application': [], 'Connection:': [], 'gzip,': [], '/58.0': [], '/wordpress': [], '/20100101': [], '/xml': [], '0.5': [], 'wordpress_test_cookie=': [], 'x64': [], '10.0': [], 'ess': [], '(Windows': [], 'text': [], '/5.0': [], 'Log+In': [], 'Content-Type:': [], 'Cookie:': [], '/xhtml+xml,application': [], 'Referer:': [], 'HTTP/1.1': [], 'Host:': [], 'en-US,en': [], 'Mozilla': [], 'NT': [], '99': [], 'Accept-Encoding:': [], 'rv:': [], 'Accept:': [], 'redirect_to=': [], 'Content-Length:': [], '/wp-login.php': [], 'User-Agent:': [], 'http:': [], '0.8': [], 'q=': [], 'keep-alive': [], 'Upgrade-Insecure-Requests:': []}

contents_dict["process"] = {'<is class=': [], '/bin': [], '8080': [], '<next': [], '/string>': [], '/struts2-rest-showcase/orders/3': [], '<redirectErrorStream>false<': [], 'User-Agent:': [], '/opmode>': [], '/iter>': [], 'Mozilla': [], '10.47.27.150:': [], 'java.lang.ProcessBuilder': [], 'BEGIN{s=': [], '<filter': [], '<value': [], 'java.util.Collections$EmptyIterator': [], '/inet/tcp': [], 'Windows NT 5.1': [], '<dataSource': [], '<command>': [], '/21509/0/0': [], 'c;close(c))while(c|getline)print|': [], '<serviceIterator': [], 'HTTP/1.1': [], '/string><string>-c<': [], '<map>': [], 'for(;': [], '<method>': [], '<cipher': [], '/command>': [], '<jdk.nashorn.internal.objects.NativeString>': [], '/next>': [], 'Host:': [], 'POST': [], '<iter': [], 'getline': [], '/redirectErrorStream>': [], '(compatible;': [], 'Content-Length:': [], 'application': [], '<string>': [], '2495': [], '/flags>': [], '<opmode>0<': [], '<': [], '<entry>': [], 's|amp;': [], 'MSIE 6.0': [], '<dataHandler>': [], '/xml': [], 'com.sun.xml.internal.ws.encoding.xml.XMLMessage$XmlDataSource': [], 'javax.crypto.NullCipher>': [], '<initialized>false<': [], 'com.sun.xml.internal.bind.v2.runtime.unmarshaller.Base64Data': [], '/sh<': [], 'javax.imageio.spi.FilterIterator>': [], '<flags>0<': [], '/initialized>': [], 'Content-Type:': [], 's;close(s)}': [], '/string><string>awk': [], 'javax.imageio.ImageIO$ContainsFilter>': [], 'javax.crypto.CipherInputStream>': [], '/4.0': []}

contents_dict["inc"] = {'mj_config[src_path]=': ['nocase', 'http_uri'], 'HTTP/1.1': [], '(Nikto': [], 'User-Agent:': [], '004284)': [], '(Test:': [], '/basebuilder': [], '/rfiinc.txt': [], 'Connection:': [], 'Mozilla': [], '(Evasions:': [], 'Keep-Alive': [], 'Host:': [], '/main.inc.php?': ['nocase', 'http_uri'], 'http:': [], '/cirt.net': [], '/2.1.5)': [], '192.168.1.108': [], '/5.00': [], 'None)': [], '/src': [], 'GET': ['http_method']}

contents_dict["sanny"] = {'0.8,image': [], 'Gecko': [], '/20081217': [], '/plain;': [], ',ko;': [], 'EUC-KR,utf-8;': [], 'Windows NT 5.1': [], '/html;': [], 'text': [], '300': [], '/xml,application': [], 'Keep-Alive:': [], '/*;': [], 'q=': [], 'gzip,deflate': [], '0.3': [], '/png,*': [], 'Accept-Encoding:': [], '1': [], 'Connection:': [], 'Accept:': [], 'Mozilla': [], 'Accept-Language: ko-kr': [], '/5.0': [], '1.8.1.20)': [], 'Accept-Charset:': [], 'rv:': [], 'p': [], 'ko;': [], '0.5': [], 'kbaksan_1': [], 'Host:': [], 'board.nboard.net': [], 'U;': [], 'Firefox': [], 'keep-alive': [], '0.7,*;': [], '(Windows;': [], 'p=': [], 'User-Agent:': [], '0.8,en-us;': [], 'HTTP/1.1': [], '/2.0.0.20': [], '/xhtml+xml,text': [], '0.7': [], '0.9,text': [], '0.5,en;': [], 'GET': [], '/list.php?db=': []}

if args.attack in contents_dict:
    contents = contents_dict[args.attack]
else:
    print("ataque sem content")

keyword_list = ("app-layer-protocol", "uricontent", "ack", "seq", "window", "ipopts", "flags", "fragbits", "fragoffset", "ttl", "tos", "itype", "icode", "icmp_id", "icmp_seq", "dsize", "flow", "threshold", "tag", "content", "pcre", "replace", "rawbytes", "byte_test", "byte_jump", "sameip", "geoip", "ip_proto", "ftpbounce", "id", "rpc", "flowvar", "flowint", "pktvar", "flowbits", "hostbits", "ipv4-csum", "tcpv4-csum", "tcpv6-csum", "udpv4-csum", "udpv6-csum", "icmpv4-csum", "icmpv6-csum", "stream_size", "detection_filter", "decode-event", "nfq_set_mark", "bsize", "tls.version", "tls.subject", "tls.issuerdn", "tls_cert_notbefore", "tls_cert_notafter", "tls_cert_expired", "tls_cert_valid", "tls.fingerprint", "tls_store", "http_protocol", "http_start", "urilen", "http_header_names", "http_accept", "http_accept_lang", "http_accept_enc", "http_connection", "http_content_len", "http_content_type", "http_referer", "http_request_line", "http_response_line", "nfs_procedure", "nfs_version", "ssh_proto", "ssh.protoversion", "ssh_software", "ssh.softwareversion", "ssl_version", "ssl_state", "byte_extract", "file_data", "pkt_data", "app-layer-event", "dce_iface", "dce_opnum", "dce_stub_data", "smb_named_pipe", "smb_share", "asn1", "engine-event", "stream-event", "filename", "fileext", "filestore", "filemagic", "filemd5", "filesha1", "filesha256", "filesize", "l3_proto", "lua", "iprep", "dns_query", "tls_sni", "tls_cert_issuer", "tls_cert_subject", "tls_cert_serial", "tls_cert_fingerprint", "ja3_hash", "ja3_string", "modbus", "cip_service", "enip_command", "dnp3_data", "dnp3_func", "dnp3_ind", "dnp3_obj", "xbits", "base64_decode", "base64_data", "krb5_err_code", "krb5_msg_type", "krb5_cname", "krb5_sname", "template2", "ftpdata_command", "bypass", "prefilter", "compress_whitespace", "strip_whitespace", "to_sha256", "depth", "distance", "within", "offset", "nocase", "fast_pattern", "startswith", "endswith", "distance", "noalert", "http_cookie", "http_method", "http_uri", "http_raw_uri", "http_header", "http_raw_header", "http_user_agent", "http_client_body", "http_stat_code", "http_stat_msg", "http_server_body", "http_host", "http_raw_host")

content_modifiers = ("http_uri", "http_raw_uri", "http_method", "http_request_line", "http_client_body", "http_header", "http_raw_header", "http_cookie", "http_user_agent", "http_host", "http_raw_host", "http_accept", "http_accept_lang", "http_accept_enc", "http_referer", "http_connection", "http_content_type", "http_content_len", "http_start", "http_protocol", "http_header_names", "http_stat_msg", "http_stat_code", "http_response_line", "http_server_body", "file_data", "nocase")

html_modifiers = ["http_method", "http_uri", "http_user_agent", "http_protocol", "http_host", "http_connection", "http_header", "http_request_line", "nocase"]

default_rule_action = "alert"
default_rule_header = "any any -> any any"
default_rule_message = "Testing rule"
rule_options = {}
default_rule_sid = 1

if str(args.attack) in ["adaptor", "coldfusion", "htaccess", "cron", "jsp", "script", "issadmin", "idq10", "system", "inc"] or "idq" in str(args.attack):
    pcapAttack = "Datasets/nikto-" + str(args.attack) + ".pcap"
else:
    pcapAttack = "Datasets/" + str(args.attack) + ".pcap"

pcapVariations = "Datasets/all-" + str(args.attack) + ".pcap"
pkts = pyshark.FileCapture(pcapAttack)
pkts.load_packets()
allpkts = pyshark.FileCapture(pcapVariations)
allpkts.load_packets()
print(len(pkts._packets))
rule_protocol = str(pkts[0].highest_layer).lower()
if rule_protocol in ["urlencoded-form"]:
    rule_protocol = "http"

if args.attack == "teardrop":
    rule_protocol = "udp"

print(rule_protocol)

# exit()


def getContentsPerModifiers(pkt):
    pkt_content_modifiers = {}

    if pkt.http.request:
        pkt_content_modifiers["http_method"] = pkt.http.request_method
        pkt_content_modifiers["http_uri"] = pkt.http.request_uri
        pkt_content_modifiers["http_user_agent"] = str(pkt.http.request_line)
        pkt_content_modifiers["http_protocol"] = pkt.http.request_version
        pkt_content_modifiers["http_host"] = "Host: " + str(pkt.http.host)
        pkt_content_modifiers["http_connection"] = "Connection: " + str(pkt.http.connection)
        pkt_content_modifiers["http_header"] = pkt_content_modifiers["http_host"] + ' ' + pkt_content_modifiers["http_user_agent"] + ' ' + pkt_content_modifiers["http_connection"]
        pkt_content_modifiers["http_request_line"] = pkt.http.chat

    for c in pkt_content_modifiers:
        if "\\xd\\xa" in pkt_content_modifiers[c]:
            pkt_content_modifiers[c] = pkt_content_modifiers[c].replace("\\xd\\xa", '')
        if "\\r\\n" in pkt_content_modifiers[c]:
            pkt_content_modifiers[c] = pkt_content_modifiers[c].replace("\\r\\n", '')

    return pkt_content_modifiers


def getTokens(pkt):
    aux_list = []

    str_data = str(binascii.unhexlify(pkt.http_raw.value))[2:][:-1]
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
        # if len(aux) > 1:
        #     for a in range(0, len(aux)-1):
        #         aux[a] = aux[a] + str(';')

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
    """aux_list = []
    for t in range(0, len(tokens)):
        aux = tokens[t].split('=')
        if len(aux) > 1:
            for a in range(0, len(aux)-1):
                aux[a] = aux[a] + str('=')

        for a in aux:
            aux_list.append(a)
    """
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

    if "/" in tokens.keys():
        del tokens["/"]

    return tokens

# tokens =getTokens(pcapAttack)
# print(tokens)
# print(len(tokens))

# exit()


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
                    if aux_key in line:
                        if keyword in keywords_freq:
                            keywords_freq[keyword] += 1
                        else:
                            keywords_freq[keyword] = 1

                for modifier in content_modifiers:
                    aux_modifier = modifier + ';'

                    if aux_modifier in line:
                        if modifier in keywords_freq:
                            keywords_freq[modifier] += 1
                        else:
                            keywords_freq[modifier] = 1

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
                contents = re.findall(r'content: \"(.+?)\"\;', line)

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
                content_count = line.count(" content: ")

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
                contents = re.findall(r'content: \"(.+?)\"\;', line)

                if " content: " in line:
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
    rare_contents_per_rule_size = {1: {1: 0}}
    contents_dict = getContentsDict()

    with open("Datasets/all_rules.txt", "r") as rule_file:
        for line in rule_file:
            if line == "\n":
                continue

            if str("alert " + rule_protocol) in line:
                line = line.strip()
                rule_size = getRuleSize(line)
                contents = re.findall(r'content: \"(.+?)\"\;', line)

                for i in range(1, 11):
                    for content in contents:
                        if contents_dict[content] == i:
                            if rule_size not in rare_contents_per_rule_size:
                                rare_contents_per_rule_size[rule_size] = {1: 0}

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

                if rule_size > max_rule_size:
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
                content_count = line.count(" content: ")

                if content_count > max_contents:
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
                content_count = line.count(" content: ")
                proto = line.split("alert ")[1].split(' ')[0]
                sid = line.split("sid: ")[1].split(";")[0]

                with open(output_file_path, 'a') as output_file:
                    output_file.write(str(sid) + "," + str(proto) + "," + str(rule_size) + "," + str(content_count)+'\n')

    return 1


rules_per_size = getRulesPerSize()
rules_per_contents = getRulesPerContents()
contents_dict = getContentsDict()
keywords_freq = getKeywordsFrequency()

sd = [(k, contents_dict[k]) for k in sorted(contents_dict, key=contents_dict.get, reverse=True)]

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
    pkt_content_modifiers = getContentsPerModifiers(pkts[0])
    html_modifiers_freq = getHtmlModifiersFreq(keywords_freq)

    # print("pkt_content_modifiers", pkt_content_modifiers)
    # print()
    # print("html_modifiers_freq: ", html_modifiers_freq)
    # print()

    # exit()

    low_case_contents_dict = getLowerCaseContentsDict()

    lower_case_pkt_content_modifiers = dict((k, v.lower()) for k, v in pkt_content_modifiers.items())
    print()

max_fitness = [0, 0, 0, 0, 0]


def ruleSizeFitness(rule):
    global rules_per_size
    rule_size = 0

    for keyword in keyword_list:
        keyword = ' ' + keyword + str(": ")
        rule_size += str(rule).count(keyword)

    fitness = 0

    if rule_size in rules_per_size:
        fitness = rules_per_size[rule_size]/max(rules_per_size.values())
    else:
        fitness = 0

    return fitness


def ruleContentsFitness(rule):
    global rules_per_contents
    content_count = str(rule).count(" content: ")
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


def testPcap(pcap):
    subprocess.Popen(["sh", "testPcap.sh", pcap], stdout=subprocess.DEVNULL).wait()


def checkAlerts(rules, pcap_dir):
    global log_file_path

    open(log_file_path, 'w').close()
    writeRuleOnFile(rules)
    testPcap(pcap_dir)

    output = [0] * len(rules)

    with open(log_file_path, "r") as logFile:
        for line in logFile:
            for idx, rule in enumerate(rules):
                if ('[1:'+str(rule.sid)+':') in line:
                    output[idx] += 1
                    break

    return output

def checkRuleAlerts(rule, log_file_dir):
    count = 0

    with open(log_file_dir, 'r') as log_file:
        for line in log_file:
            if ('[1:'+str(rule.sid)+':') in line:
                count += 1

    return count


class Rule:
    def __init__(self, action, protocol, header, message, sid):
        self.action = action
        self.protocol = protocol
        self.header = header
        self.message = message
        self.sid = sid
        self.threshold = {}
        self.fitness = []
        self.options = {}

    def __str__(self):
        str_message = "msg: \"" + self.message + "\""
        str_options = ""
        for option in self.options:
            if option == "content":
                contents = self.options["content"]
                str_content = ""
                for content in contents:
                    str_content = str_content + ' ' + str(option) + ':' + ' \"' + str(content) + '\"' + ';'
                    if len(contents[content]) > 0:
                        for i in range(0, len(contents[content])):
                            str_content = str_content + ' ' + str(contents[content][i]) + ';'
                str_options = str_options + ' ' + str_content
            elif option == "flowbits":
                flowbits = self.options[option]
                str_flowbits = ""

                for fb in flowbits:
                    str_flowbits = str_flowbits + ' ' + str(option) + ':' + str(fb) + ';'
                str_options = str_options + ' ' + str_flowbits
            else:
                if option == "pcre":
                    self.options[option] = "\"" + self.options[option] + "\""

                if str(self.options[option]) == "":
                    str_options = str_options + ' ' + str(option) + ';'
                else:
                    str_options = str_options + ' ' + str(option) + ':' + str(self.options[option]) + ';'

        if self.threshold != {}:
            str_options = str_options + ' ' + "threshold: "
            for option in self.threshold:
                str_options = str_options + ' ' + str(option) + ' ' + str(self.threshold[option]) + ','
            str_options = str_options[: -1] + ';'
        str_options = str_options + " sid: " + str(self.sid) + ';'

        str_protocol = str(self.protocol)

        return (str(self.action) + ' ' + str(str_protocol) + ' ' + str(self.header) + ' ' + '(' + str(str_message) + ';' + str_options + ')')

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
    tmp_rule = Rule("", "", "", "", "")
    golden_rule_pos = 0

    for i in range(0, len(all_rules)):
        tmp_rule = Rule("", "", "", "", "")
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

    current_pos = 0
    best_pos = math.inf
    best_rule_list = []
    best_weights = []
    all_rules_len = len(all_rules_list)
    w = []

    print("all rules len: ", all_rules_len)

    for w0 in [0, 0.25, 0.5, 0.75, 1]:
        # w.append(w0)
        for w1 in [0, 0.25, 0.5, 0.75, 1]:
            """  w.append(w1)
            for w2 in [0, 0.25, 0.5, 0.75, 1]:
                #w.append(w2)
                for w3 in [0, 0.25, 0.5, 0.75, 1]:
                    #w.append(w3)
                    for w4 in [0, 0.25, 0.5, 0.75, 1]:
                        w.append(w4)"""
            w = [w0, w1]
            # w = [w0,w1,w2,w3,w4]
            # if w != [0,0,0,0,0]:
            if w != [0, 0]:
                print("weights: ", str(w))
                all_rules_list = sorted(all_rules_list, key=partial(callGetFitness, weights=w))
                # exit()
                for x, rule in enumerate(all_rules_list):
                    if rule.sid == 1099019:
                        golden_rule_pos = all_rules_list.index(rule)
                    else:
                        rule.sid = x+1

                current_pos = all_rules_len-golden_rule_pos

                print(current_pos)

                if current_pos <= best_pos:
                    best_pos = current_pos
                    print("deepcopy start")
                    best_rule_list = copy.deepcopy(all_rules_list)
                    print("deepcopy end")
                    best_weights = copy.deepcopy(w)

    return best_rule_list, best_weights, best_pos


def sortMultipleAttacks():
    all_rules = []
    for atk in attacks_list:
        file_name = "all_rules_raw_"+str(atk)+".out"
        try:
            with open(file_name, "r") as reader:
                # all_rules.append([])
                all_rules.append(reader.readlines())
                print(file_name, "successfully loaded.")
        except:
            print(file_name, "loading failed.")
            # break

    all_rules_list = []
    tmp_str_rule = ""
    tmp_rule = Rule("", "", "", "", "")
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
            tmp_rule = Rule("", "", "", "", "")
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

    print("all rules list len: ", len(all_rules_list))

    # exit()

    all_rules_len = []
    all_pos_sum = 0
    best_all_pos_sum = math.inf
    best_all_weights = []
    best_all_pos = []

    for elem in all_rules_list:
        all_rules_len.append(len(elem))

    print("all rules len: ", all_rules_len)

    for w0 in [0, 0.25, 0.5, 0.75, 1]:
        for w1 in [0, 0.25, 0.5, 0.75, 1]:
            for w2 in [0, 0.25, 0.5, 0.75, 1]:
                for w3 in [0, 0.25, 0.5, 0.75, 1]:
                    for w4 in [0, 0.25, 0.5, 0.75, 1]:
                        all_pos_sum = 0
                        w = [w0, w1, w2, w3, w4]
                        if w != [0, 0, 0, 0, 0]:
                            print("weights: ", str(w))
                            i = 0
                            for elem in all_rules:
                                all_rules_list[i] = sorted(all_rules_list[i], key=partial(callGetFitness, weights=w))

                                for x, rule in enumerate(all_rules_list[i]):
                                    if rule.sid == 1099019:
                                        golden_rule_pos[i] = all_rules_list[i].index(rule)
                                    else:
                                        rule.sid = x+1

                                current_pos[i] = all_rules_len[i]-golden_rule_pos[i]
                                all_pos_sum += current_pos[i]
                                # print("current pos", i, ": ", current_pos[i])
                                # print("best pos: ", best_pos[i])

                                if current_pos[i] <= best_pos[i]:
                                    best_pos[i] = current_pos[i]
                                    best_rule_list[i] = all_rules_list[i].copy()
                                    best_weights[i] = w

                                i += 1
                            for i in range(len(current_pos)):
                                print(attacks_list[i]+':'+str(current_pos[i])+' ', end=' ')
                            print()

                            # print("all pos sum: ", all_pos_sum)
                            if all_pos_sum <= best_all_pos_sum:
                                best_all_pos = current_pos.copy()
                                best_all_pos_sum = all_pos_sum
                                best_rule_list = all_rules_list.copy()
                                best_all_weights = w

    print(attacks_list)

    print("best pos: ", best_pos)
    print("best weights indiv: ", best_weights)
    print("best all: ", best_all_pos_sum)
    print("best all weights: ", best_all_weights)

    for i in range(len(best_all_pos)):
        print(attacks_list[i]+' - '+str(best_all_pos[i]))

    w = best_all_weights

    print('sorting again - best all weights')

    for i in range(len(all_rules)):
        all_rules_list[i] = sorted(all_rules_list[i], key=partial(callGetFitness, weights=w))

        for x, rule in enumerate(all_rules_list[i]):
            if rule.sid == 1099019:
                golden_rule_pos[i] = all_rules_list[i].index(rule)
            else:
                rule.sid = x+1

        current_pos[i] = all_rules_len[i]-golden_rule_pos[i]

        print(attacks_list[i]+' - '+str(current_pos[i]))

    i = 0
    for rule in best_rule_list:
        i += 1
        if "1099019" in str(rule):
            golden_index = i
            print("golden index: ", golden_index, end=' ')
        # print(i, " ", str(rule))

    return best_rule_list, best_weights, best_pos


def optimizeRule(rule):
    all_rule_list = []
    new_rule = copy.deepcopy(rule)
    # if "content" in rule.options:
    #    rule.options.update(rule.options["content"])
    #    del rule.options["content"]
    # print("len options: ", len(rule.options))

    if len(rule.options) > 0:
        new_rule = copy.deepcopy(rule)
        rule_list = [new_rule]
        aux = []
        aux2 = []
        timeout = 6000
        start_time = time.time()   # inicia contador do timeout

        while time.time() - start_time < timeout:

            if not rule_list:
                break

            counter = 0

            for rules in rule_list:
                tam = 2
                clen = 0
                olen = len(rules.options)
                prob = 0

                if "content" in rule.options:
                    clen = len(rules.options["content"])
                    prob = (clen)/(clen+olen-1)
                    if olen == 1 and clen == 1:
                        tam = 1
                elif olen == 1:
                    tam = 1
                else:
                    tam = 2

                # print("olen: " + str(olen))
                # print("clen: " + str(len(rules.options["content"])))
                # print("prob: " + str(prob))

                for i in range(tam):
                    new_sid = 0
                    checker = False
                    temp = copy.deepcopy(rules)
                    if random.random() > prob:
                        elem = random.choice(list(rules.options.keys()))
                        del temp.options[elem]
                        # delete random option
                    else:
                        elem = random.choice(list(rules.options["content"].keys()))
                        del temp.options["content"][elem]
                        if len(rules.options["content"]) == 0:
                            del temp.options["content"]
                        # else:
                        #     for z in temp.options["content"]:
                        #         for g in z:
                        #             new_sid+=int(ord(g))

                    # for z in temp.options:
                    #     for g in z:
                    #         new_sid+=int(ord(g))

                    temp.message = "Testing rule {}".format(counter)

                    # if new_sid>0:
                    #     temp.sid=new_sid
                    # else:
                    #     temp.sid=counter+1
                    temp.sid = counter+1
                    # temp.sid=new_sid

                    if not aux:
                        aux.append(temp)
                        counter += 1
                    else:
                        if "content" in temp.options:
                            for z in aux:
                                if (temp.options == z.options) and (temp.options['content'] == z.options['content']):
                                    checker = True
                                    # print(temp)
                                    break
                                else:
                                    checker = False
                        else:
                            for z in aux:
                                if temp.options == z.options:
                                    checker = True
                                    break
                                else:
                                    checker = False
                        if not checker:
                            aux.append(temp)
                            # print("REGRA UNICA")
                            counter += 1
            print(len(aux))

            ec_pcap = "Datasets/positive-http.pcap"
            fitness_list = checkAlerts(aux, ec_pcap)
            for i, fitness in enumerate(fitness_list):
                if fitness < 1.0:
                    aux2.append(aux[i])
                    # print("{} : {}".format(aux[i], fitness))
                    all_rule_list.append(aux[i])

            if not aux2:
                # print(rule_list)
                break
            else:
                rule_list.clear()
                rule_list = aux2.copy()
                fitness_list.clear()
                aux2.clear()
                aux.clear()

        # print(rule_list)

    print(time.time() - start_time)

    golden_rule = copy.deepcopy(all_rule_list[0])
    golden_rule.sid = 1099019
    golden_content = {}
    golden_content["cron"] = {'GET': [], '/cron.php?': ["http_uri", "nocase"], 'include_path=': ["http_uri", "nocase"]}  # cron.php
    golden_content["htaccess"] = {'.htaccess': ["nocase", "http_uri"]}
    golden_content["jsp"] = {'/jsp/snp/': ["http_uri"], '.snp': ["http_uri"]}
    golden_content["coldfusion"] = {'GET': ["http_method", "nocase"], '/CFIDE/administrator': ["http_uri", "nocase"]}
    golden_content["adaptor"] = {'/HtmlAdaptor': ["nocase", "http_uri"], 'action=inspect': ["nocase", "http_uri"], 'bean': ["nocase", "http_uri"], 'name=': ["http_uri"]}
    golden_content["script"] = {'</script>': ["http_uri", "nocase"]}
    golden_content["issadmin"] = {'/iisadmin': ["http_uri", "nocase"]}
    golden_content["idq"] = {'.idq': ["http_uri", "nocase"]}
    golden_content["system"] = {'/system32/': ["http_uri", "nocase"]}
    golden_content["wordpress"] = {"log=": ["http_client_body"], "&pwd=": ["http_client_body"], "&wp-submit=": ["http_client_body"]}
    golden_content["process"] = {'POST': ["http_method"], 'java.lang.ProcessBuilder': ["nocase", "http_client_body", "fast_pattern"], '/struts2-rest-showcase/orders/3': ["http_uri"]}
    golden_content["inc"] = {'GET': ["http_method"], '/main.inc.php?': ["nocase", "http_uri"], 'mj_config[src_path]=': ["nocase", "http_uri"]}

    if args.attack in http_attacks:
        golden_rule.options["content"] = golden_content[args.attack]

    if args.attack == "pingscan":
        golden_rule.options = {'dsize': 0, 'itype': 8}
    elif args.attack == "blacknurse":
        golden_rule.options = {'itype': 3, 'icode': 3}
    elif args.attack == "teardrop":
        golden_rule.options = {'fragbits': 'M', 'id': 242}

    print("golden_rule: ", golden_rule)
    print("all_rules_list len: ", len(all_rule_list))
    all_rule_list.insert(0, golden_rule)
    golden_rule_pos = 0

    for i in range(0, len(all_rule_list)):
        all_rule_list[i].calculateFitness()

    with open("all_rules.out", "w+") as writer, open("all_rules_raw_"+str(args.attack)+".out", "w+") as raw_writer:
        for i in range(0, len(all_rule_list)):
            writer.write(str(all_rule_list[i])+'\n')
            raw_writer.write(str(all_rule_list[i].getAllAttributesRaw())+'\n')

    regrafit = []

    w = [1, 1, 1, 1, 1]
    print("weights: ", str(w))
    normal_rules_list = sorted(all_rule_list, key=partial(callGetFitness, weights=w))

    for x, rule in enumerate(normal_rules_list):
        if rule.sid == 1099019:
            golden_rule_pos = normal_rules_list.index(rule)
        else:
            rule.sid = x+1

    current_pos = len(normal_rules_list) - golden_rule_pos

    print("normal pos: ", current_pos)

    print("pegando precision")
    cp_pcap = "Datasets/test.pcap"
    normal_precision = checkAlerts(normal_rules_list, cp_pcap)
    print("pegando recall")
    cfn_pcap = "Datasets/all-" + args.attack + ".pcap"
    normal_recall = checkAlerts(normal_rules_list, cfn_pcap)
    print('recall golden rule:', normal_recall[golden_rule_pos])

    with open("result_"+str(args.attack)+".csv", "w+", newline='') as file:
        writer = csv.writer(file)
        writer.writerow(["Rule", "Recall", "Precision", "F1 Score"])
        for (x, y, z) in zip(normal_rules_list, normal_recall, normal_precision):
            y = y*(100/len(allpkts))
            z = 100-(z/20)
            f1 = 2*(((z*y)/100)/((y/100)+(z/100)))
            total = "{} -> recall: {}%, precision: {}%\n".format(str(x), str(y), str(z))
            writer.writerow([str(x), "{}%".format(str(y)), "{}%".format(str(z)), "{}%".format(str(f1))])

    with open("result_final_"+str(args.attack)+".csv", "w+", newline='') as file:
        with open("fitness_list_"+str(args.attack)+".csv", "w+", newline='') as fitness_file:
            with open("all_rules_raw_"+str(args.attack)+".out", "w+") as raw_writer:
                writer = csv.writer(file)
                writer.writerow(["Rule", "Recall", "Precision", "F1 Score"])
                fitness_writer = csv.writer(fitness_file)
                fitness_writer.writerow(["Rule", "Fitness1", "Fitness2", "Fitness3", "Fitness4"])

                for (x, y, z) in zip(list(reversed(normal_rules_list)), list(reversed(normal_recall)), list(reversed(normal_precision))):
                    y = y*(100/len(allpkts))
                    z = 100-(z/20)
                    f1 = 2*(((z*y)/100)/((y/100)+(z/100)))
                    if f1 > 90.0:
                        raw_writer.write(str(x.getAllAttributesRaw())+'\n')
                        total = "{} -> recall: {}%, precision: {}%\n".format(str(x), str(y), str(z))
                        writer.writerow([str(x), "{}%".format(str(y)), "{}%".format(str(z)), "{}%".format(str(f1))])
                        # fitness_writer.writerow([str(x), ruleSizeFitness(x),ruleContentsFitness(x), ruleContentsFitness(x),ruleContentsModifiersFitness(x)])
                        # regrafit.append((x, ruleSizeFitness(x),ruleContentsFitness(x), ruleContentsFitness(x), ruleContentsModifiersFitness(x)))
                        fitness_writer.writerow([str(x), ruleSizeFitness(x), ruleOptionsFitness(x)])
                        regrafit.append((x, ruleSizeFitness(x), ruleOptionsFitness(x)))

    # with open("raw_recall.txt", "w+") as writer:
    #     for x in recall:
    #         writer.write("{}\n".format(x*25))

    # with open("raw_precision.txt", "w+") as writer:
    #     for x in precision:
    #         writer.write("{}\n".format(100-(x/20)))

    # with open("raw_f1.txt", "w+") as writer:
    #     for x, y in zip(recall, precision):
    #         x=x*25
    #         y=100-(z/20)
    #         writer.write("{}\n".format(2*(((x*y)/100)/((x/100)+(y/100)))))

    # with open("output_sorted.txt", "w+") as writer:
    #     for x in all_rule_list:
    #         writer.write(str(x) + "\n")

    return rule_list[0]

# sortMultipleAttacks()
# exit()


init_rule = Rule(default_rule_action, rule_protocol, default_rule_header, default_rule_message, default_rule_sid)

"""golden_content = {}
golden_content["adaptor"] = {'/HtmlAdaptor': ["nocase", "http_uri"], 'action=inspect': ["nocase", "http_uri"], 'bean': ["nocase", "http_uri"], 'name=': ["http_uri"]}
init_rule.options["content"] = golden_content["adaptor"]
print(ruleContentsModifiersFitness(init_rule))
exit()
"""


def updateyaml():
    with open("inputs/suricata.yaml", 'r') as yaml:
        lines = yaml.readlines()
        lines[78] = "      filename: " + str(args.attack) + '.log\n'
        lines[1884] = "- " + str(args.attack) + ".rules\n"

    with open("inputs/suricata.yaml", 'w') as yaml:
        yaml.writelines(lines)


updateyaml()

def parseRules(rule_file):
    lib = ctypes.cdll.LoadLibrary("./parser.so")
    lib.Parser.argtypes = [ctypes.c_char_p]
    lib.Parser.restype = ctypes.c_char_p
    rules = []
    # with open("Datasets/all_rules.txt", 'r') as rule_file:
    with open(rule_file, 'r') as rule_file:
        r_count = 0
        for line in rule_file:
            if line != "\n":
                line = line.rstrip()
                line_b = bytes(line, 'utf-8')
                go_out = lib.Parser(ctypes.c_char_p(line_b)).decode()
                raw_rule = {}
                if go_out != "error":
                    try:
                        raw_rule = ast.literal_eval(go_out)
                        r_count += 1
                    except:
                        continue
                else:
                    continue

                rule = Rule(raw_rule["action"], raw_rule["protocol"], raw_rule["header"], raw_rule["msg"], raw_rule["sid"])

                if "threshold" in raw_rule:
                    rule.threshold = raw_rule["threshold"]

                for key in raw_rule:
                    if key not in ["metadata", "reference"]:
                        if key not in ["action", "protocol", "header", "msg", "sid", "threshold", "content", "modifiers", "sticky_buffers", "threshold"]:
                            rule.options[key] = raw_rule[key]
                        elif key == "metadata" or key == "reference":
                            rule.options[key] = ", ".join(raw_rule[key])
                        elif key == "content":
                            contents = {}
                            i = 0
                            for c in raw_rule[key]:
                                if raw_rule["modifiers"][i] != []:
                                    contents[c] = raw_rule["modifiers"][i]
                                i += 1
                            rule.options["content"] = contents
                        elif key == "threshold":
                            rule.threshold = raw_rule[key]

                rules.append(rule)

    return rules


def parsePacket(pkt_raw, pkt):
    pkt_proto = ""
    for l in pkt_raw.layers:
        if "_raw" not in l._layer_name:
            pkt_proto = l._layer_name

    rule = Rule(default_rule_action, "proto", default_rule_header, default_rule_message, default_rule_sid)

    for pkt_layer in pkt.layers:
        if pkt_layer._layer_name == "ip":
            rule.protocol = "IP"
            rule.message = "IP Rule"
            ip_pkt = pkt.ip
            # rule.options["fragbits"] =
            rule.options["fragoffset"] = ip_pkt.frag_offset
            rule.options["ip_proto"] = ip_pkt.proto
            rule.options["ttl"] = ip_pkt.ttl
            rule.options["id"] = int(ip_pkt.id, 0)
            rule.options["tos"] = int(ip_pkt.dsfield, 0)

    if pkt_proto == "icmp":
        rule.protocol = "icmp"
        rule.message = "ICMP Rule"

        try:
            del rule.options["ip_proto"]
        except:
            pass

        icmp_pkt = pkt_raw.icmp
        rule.options["itype"] = icmp_pkt.type
        rule.options["icmp_seq"] = icmp_pkt.seq
        rule.options["icode"] = icmp_pkt.code
        rule.options["icmp_id"] = icmp_pkt.ident
        rule.options["dsize"] = icmp_pkt.data_len

        if ip_pkt.src == ip_pkt.dst:
            rule.options["sameip"] = ""

    elif pkt_proto == "http":
        rule.protocol = "http"
        rule.message = "HTTP Rule"

        rule.options = {}

        tokens = getTokens(pkt_raw)
        rule.options["content"] = tokens
        # http_modifiers = getContentsPerModifiers(pkt)
    elif pkt_proto == "tcp":
        rule.protocol = "tcp"
        rule.message = "TCP Rule"

        tcp_pkt = pkt_raw.tcp

        try:
            del rule.options["ip_proto"]
        except:
            pass

        tcp_flags = ''

        if int(tcp_pkt.flags, 0) == 0:
            tcp_flags = 0
        else:
            if int(tcp_pkt.flags, 0) & 1:
                tcp_flags += 'F'
            if int(tcp_pkt.flags, 0) & 2:
                tcp_flags += 'S'
            if int(tcp_pkt.flags, 0) & 4:
                tcp_flags += 'R'
            if int(tcp_pkt.flags, 0) & 8:
                tcp_flags += 'P'
            if int(tcp_pkt.flags, 0) & 16:
                tcp_flags += 'A'
            if int(tcp_pkt.flags, 0) & 32:
                tcp_flags += 'U'
            if int(tcp_pkt.flags, 0) & 64:
                tcp_flags += 'E'
            if int(tcp_pkt.flags, 0) & 128:
                tcp_flags += 'C'
            # if int(tcp_pkt.flags, 0) & 256:
            #     tcp_flags += 'N'

        # rule.options["seq"] = tcp_pkt.seq
        # rule.options["ack"] = tcp_pkt.ack
        rule.options["window"] = tcp_pkt.window_size
        rule.options["flags"] = tcp_flags

        """try:
            #suricata >5
            rule.options["tcp.mss"] = tcp_pkt.options_mss_val
        except:
            pass
        """
    else:
        print("unsupported protocol")

    return rule


def allPktsRule(pcap_dir):
    pkts = pyshark.FileCapture(pcap_dir)
    pkts_raw = pyshark.FileCapture(pcap_dir, include_raw=True, use_json=True)
    pkts.load_packets()
    pkts_raw.load_packets()

    rules = []

    for i in range(len(pkts)):
        pkt = pkts[i]
        pkt_raw = pkts_raw[i]
        rule = parsePacket(pkt_raw, pkt)
        rules.append(rule)

    for r in rules:
        print(r.options["content"].keys())
        print()

    common_contents = {}
    common_options = {}

    for r in rules:
        for key in r.options:
            if key == "content":
                if common_contents == {}:
                    common_contents.update(r.options["content"])
                else:
                    intersection = set(common_contents) & set(r.options["content"])
                    aux_contents_dict = deepcopy(common_contents)
                    common_contents = {}
                    for elem in intersection:
                        common_contents[elem] = aux_contents_dict[elem]
            else:
                value = r.options[key]
                if key in common_options:
                    if common_options[key] != value:
                        common_options[key] == "to remove"
                else:
                    common_options[key] = value

    # print("intersection: ", intersection)
    # print()

    for key in common_options:
        if common_options[key] == "to remove":
            del common_options[key]

    # print(common_contents)
    # print(len(common_contents))
    # exit()

    rules[0].message = "All " + rules[0].message
    rules[0].options = common_options
    rules[0].options["content"] = common_contents

    print(rules[0])
    print()

    return rules[0]


def onlyMalignRule(malign_pcap, fp_pcap):
    # missing non-content options
    fp_pkt = pyshark.FileCapture(fp_pcap)
    fp_pkt_raw = pyshark.FileCapture(fp_pcap, include_raw=True, use_json=True)
    fp_pkt.load_packets()
    fp_pkt_raw.load_packets()
    fp_pkt = fp_pkt[0]
    fp_pkt_raw = fp_pkt_raw[0]

    all_malign_rule = allPktsRule(malign_pcap)
    fp_rule = parsePacket(fp_pkt_raw, fp_pkt)
    print("fp contents: ", fp_rule.options["content"].keys())
    print("tp contents: ", all_malign_rule.options["content"].keys())
    only_malign_contents = list(set(all_malign_rule.options["content"]) - set(fp_rule.options["content"]))

    print("omc", only_malign_contents)
    print()

    only_malign_rule = deepcopy(all_malign_rule)

    aux_content = deepcopy(only_malign_rule.options["content"])

    for c in aux_content:
        if c not in only_malign_contents:
            del only_malign_rule.options["content"][c]

    return only_malign_rule


def fixRule():
    rule_file = "tests/tofix.rule"
    fp_rule = parseRules(rule_file)

    if len(fp_rule) == 0:
        print("no rule parsed")
        exit()
    elif len(fp_rule) == 1:
        fp_rule = fp_rule[0]
        print(fp_rule)
        print()
    else:
        print("multiple rules parsed")
        exit()

    fp_pcap = "tests/false-positive.pcap"
    tp_pcap = "tests/true-positives.pcap"
    tp_rule = onlyMalignRule(tp_pcap, fp_pcap)
    print(tp_rule)
    print()
    # exit()
    count = 0
    for c in tp_rule.options["content"]:
        aux_rule = deepcopy(fp_rule)
        aux_rule.message = "Testing rule {}".format(count)
        if c not in aux_rule.options["content"]:
            global log_file_path
            aux_rule.options["content"][c] = tp_rule.options["content"][c]

            aux_rule_list = [aux_rule]
            writeRuleOnFile(aux_rule_list)
            testPcap("tests/false-positive.pcap")
            alerts_count = checkRuleAlerts(aux_rule, log_file_path)

            if alerts_count > 0:
                continue
            else:
                writeRuleOnFile(aux_rule_list)
                testPcap("tests/true-positives.pcap")
                alerts_count = checkRuleAlerts(aux_rule, log_file_path)
                # print("false negative check output: ", output, alerts_count)

                if alerts_count == 1:
                    print(aux_rule)
                    print()
                    pass
        count += 1
    print(fp_rule)


# fixRule()
# exit()

final_rule = init_rule
if len(pkts._packets) > 1:
    if args.attack == "synflood":
        synflood_options = {'window': 512, 'flags': 'S'}
        final_rule.options = synflood_options
    elif args.attack == "blacknurse":
        blacknurse_options = {'dsize': 28, 'ttl': 64, 'itype': 3, 'icode': 3}
        final_rule.options = blacknurse_options

    final_rule.threshold = {'type': 'both', 'track': 'by_dst', 'count': len(pkts._packets), 'seconds': 5}
    print(final_rule)
    final_rule = optimizeRule(final_rule)
else:
    if rule_protocol == "http":
        final_rule.options["content"] = contents

    if args.attack == "pingscan":
        pingscan_options = {'dsize': 0, 'itype': 8, 'icode': 0, 'icmp_id': 23570, 'icmp_seq': 3439}
        final_rule.options = pingscan_options
    elif args.attack == "teardrop":
        teardrop_options = {'dsize': 0, 'fragbits': 'M', 'id': 242, 'ttl': 64}
        final_rule.options = teardrop_options

    print("initial rule: \n", final_rule)

    final_rule = optimizeRule(final_rule)

if final_rule.threshold != {} and final_rule.threshold["count"] == 1:
    final_rule.threshold = {}

time_end = time.time()

print("max fits: ")
print(max_fitness)

print("Exec time: ", time_end - time_begin)
