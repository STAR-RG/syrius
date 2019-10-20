import subprocess
import time
import copy
import pyshark
from itertools import combinations

keys_by_proto = {}
keys_by_proto["icmp"] = {"dsize":1480, "itype":255, "icode":255}#,"icmp_seq":65525, "icmp_id":65535}
keys_by_proto["tcp"] = {"window": 65525, "flags":['F', 'S', 'R', 'P', 'A', 'U', 'C', 'E', '0']}#"ack":4294967295, "seq":4294967295}
keys_by_proto["udp"] = {"fragbits": ['D', 'R', 'M']}
threshold = {"type":["limit", "threshold", "both"], "track":["by_src", "by_dst"], "count": 65535, "seconds": 1}

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

def writeRuleOnFile(rule):
    ruleFile_path = "../suricata/pesquisa/individual.rules"
    ruleFile = open(ruleFile_path, 'w+')
    ruleFile.write(str(rule))
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
    reloadSuricataRules()  
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

def sendGoodTraffic(local_ip):
    subprocess.Popen(["sudo", "sh", "sendGoodTraffic.sh"], stdout=subprocess.DEVNULL).wait()
    time.sleep(12)

def evalFalsePositive(rule):
    fitnessFile_path = "../suricata/rulesFitness.txt"
    subprocess.Popen(["sudo", "rm", "../suricata/rulesFitness.txt"], stdout=subprocess.DEVNULL).wait()
    writeRuleOnFile(rule)
    reloadSuricataRules() 
    sendGoodTraffic(getLocalIp())

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
            str_options = str_options + ' ' + str(option) + ':' + str(self.options[option]) + ';'

        if self.threshold != {}:
            str_options = str_options + ' ' + "threshold:"
            for option in self.threshold:
                str_options = str_options + ' ' + str(option) + ' ' + str(self.threshold[option]) + ','
            str_options = str_options[:-1] + ';'
        str_options = str_options + ' ' + "sid:" + str(self.sid) + ';'

        return (str(self.action) + ' ' + str(self.protocol) + ' ' + str(self.header) + ' ' + '(' + str(self.message) + str_options + ')')

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

def optimizeRule(rule):
    new_rule = copy.deepcopy(rule)
    #print("len options:", len(rule.options))
    if len(rule.options) > 1:
        for keyword in rule.options:
            if len(new_rule.options) == 1:
                break
            del new_rule.options[keyword]
            print(str(new_rule))

            fitness = evalFalsePositive(new_rule)
            print("#4 - rule fitness: " + str(fitness))
            if fitness >= 1.0:
                new_rule.options[keyword] = rule.options[keyword]
    
    return new_rule

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

init_rule = Rule(default_rule_action, rule_protocol, default_rule_header, default_rule_message, default_rule_sid)
#init_rule.threshold = {"type": "both", "track": "by_dst", "count": 1, "seconds": 1}
print("initial rule: " + str(init_rule))

#final_rule = evolveRuleSinglePacket(init_rule)
#final_rule = optimizeRule(final_rule)
final_rule = evolveRuleFlood(init_rule)

if final_rule.threshold != {} and final_rule.threshold["count"] == 1:
    final_rule.threshold = {} 

print("final rule: " + str(final_rule))

print()