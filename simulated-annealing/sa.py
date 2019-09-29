import subprocess
import time
import copy

keys_by_proto = {}
keys_by_proto["icmp"] = {"dsize":1480, "itype":255, "icode":255, "icmp_seq":65525}#, "icmp_id":65535}
# keys_by_proto["tcp"] = ["flow", "flags", "flowbits", "byte_test", "threshold", "seq", "ack", "window"]
threshold = {"type":["limit", "threshold", "both"], "track":["by_src", "by_dst"], "count": 65535, "seconds": 1}

default_rule_action = "alert"
default_rule_header = "any any -> any any"
default_rule_message = "msg:\"Testing rule\";"
rule_options = {}
default_rule_sid = 1

#subprocess.Popen(["sudo", "suricata", "-c", "../suricata/suricata.yaml", "-i", "wlp2s0"])

def writeRuleOnFile(rule):
    ruleFile_path = "../suricata/pesquisa/individual.rules"
    ruleFile = open(ruleFile_path, 'w+')
    ruleFile.write(str(rule))
    ruleFile.close()
    time.sleep(0.050)

def reloadSuricataRules(suricata_pid):
    subprocess.Popen(["sudo", "kill", "-USR2", str(suricata_pid)])
    time.sleep(0.200)

def getSuricataPid():
    return int(subprocess.Popen(["pidof", "suricata"], stdout=subprocess.PIPE, encoding="utf-8").communicate()[0])

def getLocalIp():
    return subprocess.Popen(["sh", "getLocalIp.sh"], stdout=subprocess.PIPE, encoding="utf-8").communicate()[0].rstrip()

def sendFlood(local_ip):
    subprocess.Popen(["sh", "sendFlood.sh", str(local_ip)], stdout=subprocess.DEVNULL).wait()
    time.sleep(0.1)

def sendPacket(local_ip):
    subprocess.Popen(["sh", "sendPacket.sh", str(local_ip)], stdout=subprocess.DEVNULL).wait()

def getRuleFitness(keywords):
    if len(keywords) <= 1:
        return 0
    
    for i in range(0, len(keywords)):
        keywords[i] = keywords[i].split(" ")
        while '' in keywords[i]:
            keywords[i].remove('')

        keywords[i][0] = keywords[i][0][:-1]
    
    fitness = 0
    for i in range(1, len(keywords)):
        fitness = fitness + float(keywords[i][1])
    
    fitness = fitness/(len(keywords)-1)

    return fitness

def evalRule(rule):
    subprocess.Popen(["sudo", "rm", "../suricata/rulesFitness.txt"], stdout=subprocess.DEVNULL).wait()
    writeRuleOnFile(rule)
    reloadSuricataRules(getSuricataPid())    
    #sendPacket(getLocalIp())    
    sendFlood(getLocalIp())
    fitnessFile_path = "../suricata/rulesFitness.txt"

    try:
        fitnessFile = open(fitnessFile_path, "r")
    except IOError:
        return 0, 0
    
    lines = fitnessFile.readlines()
    fitness = 0
    matches = 0
    for line in lines:
        line = line.rstrip('\n')
        keywords = line.split("-")
        if rule.threshold == {}:
            for key in keywords:
                if "threshold" in key:
                    keywords = keywords[:-1]
                    break
        #print(keywords)
        if keywords != ['']:
            fitness = getRuleFitness(keywords)

        if fitness == 1:
            matches += 1 
    
    return fitness, matches

def sendGoodTraffic(local_ip):
    #subprocess.Popen(["sh", "setDstAddr.sh", str(local_ip)], stdout=subprocess.DEVNULL).wait()
    subprocess.Popen(["sudo", "sh", "sendGoodTraffic.sh"], stdout=subprocess.DEVNULL).wait()
    time.sleep(11)

def evalFalsePositive(rule):
    fitnessFile_path = "../suricata/rulesFitness.txt"
    subprocess.Popen(["sudo", "rm", "../suricata/rulesFitness.txt"], stdout=subprocess.DEVNULL).wait()
    writeRuleOnFile(rule)
    reloadSuricataRules(getSuricataPid()) 
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
            self.options[keyword] = 0

            print(str(self))
            fitness1 = evalRule(self)
            fitness2 = evalRule(self)

            if fitness1 == fitness2:
                rule_options[keyword] = 0

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
        while rule.options[keyword] < keys_by_proto[rule.protocol][keyword]:
            rule.options[keyword] = rule.options[keyword]+1
            print(str(rule))

            new_fitness, new_matches = evalRule(rule)
            print("rule fitness: " + str(new_fitness) + " matches: " + str(new_matches))
            
            if new_fitness < 1 and new_matches > 0:
                del rule.options[keyword]
                break

            if new_fitness < prev_fitness:
                rule.options[keyword] = rule.options[keyword]-1
                break
            else:
                prev_fitness = new_fitness
    return rule  

def optimizeRule(rule):
    new_rule = copy.deepcopy(rule)
    for keyword in rule.options:
        del new_rule.options[keyword]
        print(str(new_rule))

        fitness = evalFalsePositive(new_rule)
        print(fitness)
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
    print("rule fitness: " + str(new_fitness) + " matches: " + str(matches))
    
    while 1:
        new_rule.threshold["count"] += 1
        new_fitness, matches = evalRule(new_rule)
        print(str(new_rule))
        print("rule fitness: " + str(new_fitness) + " matches: " + str(matches))

        if new_fitness == 1 and matches == 1:
            break
    
    return new_rule

init_rule = Rule(default_rule_action, "icmp", default_rule_header, default_rule_message, default_rule_sid)
#init_rule.threshold = {"type": "both", "track": "by_dst", "count": 1, "seconds": 1}
print("initial rule: " + str(init_rule))

#final_rule = evolveRuleSinglePacket(init_rule)
#final_rule = optimizeRule(final_rule)
final_rule = evolveRuleFlood(init_rule)

if final_rule.threshold != {} and final_rule.threshold["count"] == 1:
    final_rule.threshold = {} 

print("final rule: " + str(final_rule))

print()