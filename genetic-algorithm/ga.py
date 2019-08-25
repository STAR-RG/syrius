import random
import numpy
import subprocess
import time

from deap import base
from deap import creator
from deap import tools

icmp_keywords = ["itype", "icode", "icmp_seq", "icmp_id", "id"]

class Rule:
    
    def __init__(self, action, header, message, options, sid):
        self.action = action
        self.header = header
        self.message = message
        self.options = options
        self.sid = sid
    
    def __str__(self):
        str_options = self.message
        for op in self.options:
            str_options = str_options + ' ' + str(op[0]) + str(op[1]) + str(op[2]) + ';'

        str_options = str_options + ' ' + "sid:" + str(self.sid) + ';'

        return (str(self.action) + ' ' + str(self.header) + ' ' + '(' + str_options + ')')

rule_action = "alert"
rule_header = "icmp $EXTERNAL_NET any -> $HOME_NET any"
rule_message = "msg:\"Testing rule\";"
rule_options = []
rule_sid = 0

def rule_to_string(rule):
    #print(rule)
    #global rule_sid
    
    str_rule = ""
    for option in rule:
        if option[0] == "sid":
            rule_sid = option[2]
            continue
        
        str_rule = str_rule + ' '
        for i in option:
            str_rule = str_rule + str(i)
        
        str_rule = str_rule + ';'

    return (rule_action + ' ' + rule_header + ' ' + '(' + rule_message + str_rule + ' ' + "sid:" + str(rule_sid) + ';' + ')')

#subprocess.Popen(["sudo", "suricata", "-c", "../suricata/suricata.yaml", "-i", "wlp2s0"])

time.sleep(.250)

local_ip = subprocess.Popen(["sh", "getLocalIp.sh"], stdout=subprocess.PIPE, encoding="utf-8").communicate()[0].rstrip()

suricata_pid = int(subprocess.Popen(["pidof", "suricata"], stdout=subprocess.PIPE, encoding="utf-8").communicate()[0])

def parseRule(rule):
    for i in range(0, len(rule)):
        for j in range(i+1, len(rule)):
            if rule[i][0] == rule[j][0]:
                return 0
    
    return 1

def evalRule(rule):
    #print("Evaluating Rule")
    
    global suricata_pid
    global local_ip

    #print("suricata pid:", suricata_pid)
    #print(rule)

    if parseRule(rule) == 1:
        ruleFile_path = "../suricata/pesquisa/individual.rules"
        ruleFile = open(ruleFile_path, 'w+')
        #print(rule_to_string(rule))
        ruleFile.write(rule_to_string(rule))
        ruleFile.close()

        subprocess.Popen(["sudo", "kill", "-USR2", str(suricata_pid)])
        time.sleep(0.200)

        subprocess.Popen(["sh", "sendPacket.sh", str(local_ip)], stdout=subprocess.DEVNULL).wait()
        #time.sleep(.05)

        fitnessFile_path = "../suricata/rulesFitness.txt"
        fitnessFile = open(fitnessFile_path, "r")

        line = (fitnessFile.readline()).rstrip('\n')
        #print(line)
        keywords = line.split("-")

        for i in range(0, len(keywords)):
            keywords[i] = keywords[i].split(" ")
            while '' in keywords[i]:
                keywords[i].remove('')

            keywords[i][0] = keywords[i][0][:-1]
        
        matches = 0
        for i in range(1, len(keywords)):
            matches = matches + int(keywords[i][1])
        
        #print(keywords)
        #print(str(keywords[0][0]) + ": " + str(keywords[0][1]) + " - " "fitness: " + str(matches/len(keywords)))
        if matches/(len(keywords)-1) > 0:
            print(rule_to_string(rule))
            print("fitness: " + str(matches/len(keywords)))

    else:
        print("Bad rule format.")

def generateRandomKeyword():
    keyword = random.choice(icmp_keywords)
    #print(keyword)
    colon = ':'
    if (keyword == "itype"):
        max_keyword_val = 255
    elif (keyword == "icode"):
        max_keyword_val = 255
        colon = random.choice([':', ':>'])
    else:
        max_keyword_val = 65535

    return (str(keyword), colon, random.randint(0, max_keyword_val))

def generateKeywordList():
    global rule_sid
    rule_sid = rule_sid+1
    keyword_dict = {}
    keyword_dict["sid"] = ("sid", ':', rule_sid)
    for i in range(0, random.randint(1, len(icmp_keywords))):
        while 1:
            keyword = generateRandomKeyword()
        
            if keyword[0] not in keyword_dict:
                keyword_dict[keyword[0]] = keyword
                break
    
    keyword_list = [v for v in keyword_dict.values()]

    return keyword_list

#print(rule_options)

#new_rule = Rule(rule_action, rule_header, rule_message, rule_options, rule_sid)
#print(new_rule)

creator.create("Fitness", base.Fitness, weights=(1.0,))
creator.create("Individual", list, fitness=creator.Fitness)

toolbox = base.Toolbox()

test_dict = []

#toolbox.register("keyword", random.choice, keywords)
toolbox.register("individual", generateKeywordList)
toolbox.register("population", tools.initRepeat, list, toolbox.individual)
toolbox.register("evaluate", evalRule)

#individual = toolbox.individual()

#print(individual)

pop = toolbox.population(n=1000)
ind_test = [("itype", ':', 41), ("icmp_id", ':', 47486), ("icode", ":>", 215), ("icmp_seq", ':', 25423)]
#toolbox.evaluate(ind_test)

for ind in pop:
    toolbox.evaluate(ind)

#print(*pop, sep='\n')