import subprocess
import time

from simanneal import Annealer

icmp_keywords = ["itype", "icode", "icmp_seq", "icmp_id", "dsize"]

default_rule_action = "alert"
default_rule_header = "icmp any any -> any any"
default_rule_message = "msg:\"Testing rule\";"
rule_options = {}
default_rule_sid = 1

#subprocess.Popen(["sudo", "suricata", "-c", "../suricata/suricata.yaml", "-i", "wlp2s0"])

def evalRule(rule):
    local_ip = subprocess.Popen(["sh", "getLocalIp.sh"], stdout=subprocess.PIPE, encoding="utf-8").communicate()[0].rstrip()

    suricata_pid = int(subprocess.Popen(["pidof", "suricata"], stdout=subprocess.PIPE, encoding="utf-8").communicate()[0])

    ruleFile_path = "../suricata/pesquisa/individual.rules"
    ruleFile = open(ruleFile_path, 'w+')
    ruleFile.write(str(rule))
    ruleFile.close()

    time.sleep(0.050)

    subprocess.Popen(["sudo", "kill", "-USR2", str(suricata_pid)])
    time.sleep(0.200)


    subprocess.Popen(["sh", "sendPacket.sh", str(local_ip)], stdout=subprocess.DEVNULL).wait()
    time.sleep(0.050)

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
    def __init__(self, action, header, message, options, sid):
        self.action = action
        self.header = header
        self.message = message
        self.options = options
        self.sid = sid
        self.fitness = 0
    
    def __str__(self):
        str_options = ""
        for option in self.options:
            str_options = str_options + ' ' + str(option) + ':' + str(self.options[option]) + ';'

        str_options = str_options + ' ' + "sid:" + str(self.sid) + ';'

        return (str(self.action) + ' ' + str(self.header) + ' ' + '(' + str(self.message) + str_options + ')')


init_rule = Rule(default_rule_action, default_rule_header, default_rule_message, {}, default_rule_sid)

for keyword in icmp_keywords:
    init_rule.options = {}
    init_rule.options[keyword] = 0

    fitness1 = evalRule(init_rule)
    fitness2 = evalRule(init_rule)

    if fitness1 == fitness2:
        rule_options[keyword] = 0

print(rule_options)

init_rule = Rule(default_rule_action, default_rule_header, default_rule_message, rule_options, default_rule_sid)

print("init_rule: " + str(init_rule))

init_fitness = evalRule(init_rule)
print("initial: fitness: " + str(init_fitness))

prev_fitness = init_fitness
for keyword in init_rule.options:
    while 1:
        init_rule.options[keyword] = init_rule.options[keyword]+1
        print(str(init_rule))

        new_fitness = evalRule(init_rule)
        print("rule fitness: " + str(new_fitness))

        if new_fitness < prev_fitness:
            init_rule.options[keyword] = init_rule.options[keyword]-1
            break
        else:
            prev_fitness = new_fitness

evalRule(init_rule)

print(init_rule)