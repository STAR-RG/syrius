import random
import numpy
import subprocess
import time

from deap import algorithms
from deap import base
from deap import creator
from deap import tools

icmp_keywords = ["itype", "icode", "icmp_seq", "icmp_id"]
MIN_RULE_SIZE = 2
MAX_RULE_SIZE = len(icmp_keywords) + 1

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
    str_rule = ""
    sid = 0
    for option in rule:
        #print(str_rule)
        if option[0] == "sid":
            sid = option[2]
            continue
        
        str_rule = str_rule + ' '
        for i in option:
            str_rule = str_rule + str(i)
        
        str_rule = str_rule + ';'

    rule_str = (rule_action + ' ' + rule_header + ' ' + '(' + rule_message + str_rule + ' ' + "sid:" + str(sid) + ';' + ')')
    #print(rule_str) 
    return rule_str

#subprocess.Popen(["sudo", "suricata", "-c", "../suricata/suricata.yaml", "-i", "wlp2s0"])

time.sleep(.250)

local_ip = subprocess.Popen(["sh", "getLocalIp.sh"], stdout=subprocess.PIPE, encoding="utf-8").communicate()[0].rstrip()

suricata_pid = int(subprocess.Popen(["pidof", "suricata"], stdout=subprocess.PIPE, encoding="utf-8").communicate()[0])

def mutRule(rule):
    """Mutation remove, add or modify a keyword"""
    rnd = random.random()
    global MIN_RULE_SIZE
    global MAX_RULE_SIZE
    if len(rule) == MIN_RULE_SIZE:
        rnd = random.uniform(0.33, 1.0)
    elif len(rule) == MAX_RULE_SIZE:
        rnd = random.uniform(0.0, 0.66)
    else:
        rnd = random.random()

    if rnd < 0.33:
        #print("removing")
        while 1:
            key = random.choice(rule)
            
            if key[0] != "sid":
                break
        rule.remove(key)
    
    elif 0.33 <= rnd <= 0.66:
        #print("modifying")
        #print(rule)
        while 1:
            keyword = random.choice(rule)

            if keyword[0] != "sid":
                break 

        rule.remove(keyword)

        colon = ':'
        if (keyword[0] == "itype"):
            max_keyword_val = 255
        elif (keyword[0] == "icode"):
            max_keyword_val = 255
            colon = random.choice([':', ':>'])
        else:
            max_keyword_val = 65535
        
        keyword = (keyword[0], colon, random.randint(0, max_keyword_val))

        rule.append(keyword)
    
    elif rnd > 0.66:
        #print("adding")
        #print(rule)
        while 1:
            keyword = generateRandomKeyword()
        
            if keyword[0] not in [key[0] for key in rule]:
                rule.append(keyword)
                break

    

    return rule,

def cxRule(rule1, rule2):
    #print("cxRule")
    key1 = random.choice([key for key in rule1 if key[0] != "sid"])

    if key1[0] not in [key[0] for key in rule2]:
        rule2.append(key1)
    else:
        for key in rule2:
            if key1[0] == key[0]:
                rule2.remove(key)
                rule2.append(key1)
                rule1.remove(key1)
                rule1.append(key)
                return rule1, rule2 

    key_list = [key for key in rule2 if (key[0] != "sid" and key not in rule1)]
    #print("key:", key_list)

    if len(key_list) > 0:
        key2 = random.choice(key_list)

        if key2[0] not in [key[0] for key in rule1]:
            rule1.append(key2)
        else:
            for key in rule1:
                if key2[0] == key[0]:
                    rule1.remove(key)
                    rule1.append(key2)
                    rule2.remove(key2)
                    rule2.append(key)
                    break

    return rule1, rule2 

def parseRule(rule):
    #print(rule)
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

        #print(str(local_ip))

        subprocess.Popen(["sh", "sendPacket.sh", str(local_ip)], stdout=subprocess.DEVNULL).wait()
        time.sleep(0.050)

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
        
        if matches/(len(icmp_keywords)) > 0:
            print(rule_to_string(rule))
            print("fitness: " + str(matches/len(keywords)))

        return 1, matches/(len(keywords)-1)

    else:
        print("Bad rule format.")

def generateRandomKeyword():
    global icmp_keywords
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
    global icmp_keywords
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

    #print(keyword_list)

    return keyword_list

#print(rule_options)

#new_rule = Rule(rule_action, rule_header, rule_message, rule_options, rule_sid)
#print(new_rule)

creator.create("Fitness", base.Fitness, weights=(1.0,))
creator.create("Individual", list, fitness=creator.Fitness)

toolbox = base.Toolbox()

test_dict = []

toolbox.register("keywords", generateKeywordList)
toolbox.register("individual", tools.initIterate, creator.Individual, toolbox.keywords)
toolbox.register("population", tools.initRepeat, list, toolbox.individual)
toolbox.register("evaluate", evalRule)
toolbox.register("mate", cxRule)
toolbox.register("mutate", mutRule)
toolbox.register("select", tools.selNSGA2)


"""for i in range(0, 1):
    print(i)
    ind1 = [('sid', ':', 1), ('icode', ':>', 62)]
    ind2 = [('sid', ':', 2), ('icmp_seq', ':', 14265), ('icmp_id', ':', 52634), ('id', ':', 897), ('icode', ':', 244)]
    print(ind1)
    print(ind2)

    if parseRule(ind1) == 0:
        print("original rule1 bad format:")
        print(ind1)
    
    if parseRule(ind2) == 0:
        print("original rule2 bad format:")
        print(ind2)

    ind1, ind2 = toolbox.mate(ind1, ind2)
    
    if parseRule(ind1) == 0:
        print("mate rule1 bad format:")
        print(ind1)
   
    if parseRule(ind2) == 0:
        print("mate rule2 bad format:")
        print(ind2)
    
    print(ind1)
    print(ind2)
"""


pop = toolbox.population(n=20)

new_pop = algorithms.eaSimple(pop, toolbox, cxpb=0.5, mutpb=0.5, ngen=10, verbose=True)

print(*pop, sep='\n')
print()
print(*new_pop[0], sep='\n')