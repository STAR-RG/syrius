import subprocess
import time

keys_by_proto = {}
keys_by_proto["icmp"] = {"itype":255, "icode":255, "icmp_seq":65525, "icmp_id":65535, "dsize":1480}
# keys_by_proto["tcp"] = ["flow", "flags", "flowbits", "byte_test", "threshold", "seq", "ack", "window"]

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

def sendPacket(local_ip):
    subprocess.Popen(["sh", "sendPacket.sh", str(local_ip)], stdout=subprocess.DEVNULL).wait()

def evalRule(rule):
    writeRuleOnFile(rule)
    reloadSuricataRules(getSuricataPid())    
    sendPacket(getLocalIp())    

    fitnessFile_path = "../suricata/rulesFitness.txt"
    fitnessFile = open(fitnessFile_path, "r")

    line = (fitnessFile.readline()).rstrip('\n')
    print(line)
    keywords = line.split("-")

    for i in range(0, len(keywords)):
        keywords[i] = keywords[i].split(" ")
        while '' in keywords[i]:
            keywords[i].remove('')

        keywords[i][0] = keywords[i][0][:-1]
    
    fitness = 0
    for i in range(1, len(keywords)):
        fitness = fitness + float(keywords[i][1])
    
    return (fitness/(len(keywords)-1))

class Rule:    
    def __init__(self, action, protocol, header, message, sid):
        self.protocol = protocol
        self.action = action
        self.header = header
        self.message = message
        self.sid = sid
        self.fitness = 0

        rule_options = {}
        for keyword in keys_by_proto[protocol]:
            self.options = {}
            self.options[keyword] = 0

            fitness1 = evalRule(self)
            fitness2 = evalRule(self)

            if fitness1 == fitness2:
                rule_options[keyword] = 0

        self.options = rule_options
    
    def __str__(self):
        str_options = ""
        for option in self.options:
            str_options = str_options + ' ' + str(option) + ':' + str(self.options[option]) + ';'

        str_options = str_options + ' ' + "sid:" + str(self.sid) + ';'

        return (str(self.action) + ' ' + str(self.protocol) + ' ' + str(self.header) + ' ' + '(' + str(self.message) + str_options + ')')

rule = Rule(default_rule_action, "icmp", default_rule_header, default_rule_message, default_rule_sid)

print("rule: " + str(rule))

init_fitness = evalRule(rule)
print("initial: fitness: " + str(init_fitness))

prev_fitness = init_fitness
for keyword in rule.options:
    while rule.options[keyword] < keys_by_proto[rule.protocol][keyword]:
        rule.options[keyword] = rule.options[keyword]+1
        print(str(rule))

        new_fitness = evalRule(rule)
        print("rule fitness: " + str(new_fitness))

        if new_fitness < prev_fitness:
            rule.options[keyword] = rule.options[keyword]-1
            break
        else:
            prev_fitness = new_fitness

evalRule(rule)

print(rule)
