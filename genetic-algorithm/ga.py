import random
import numpy
import subprocess

from deap import base
from deap import creator
from deap import tools

icmp_keywords = ["itype", "icode", "icmp_seq", "icmp_id", "dsize", "id"]

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
rule_sid = 1

def rule_to_string(rule):
    #print(rule)
    str_rule = ""
    for option in rule:
        str_rule = str_rule + ' '
        for i in option:
            str_rule = str_rule + str(i)
        str_rule = str_rule + ';'

    return (rule_action + ' ' + rule_header + ' ' + '(' + rule_message + str_rule + ' ' + "sid:" + str(rule_sid) + ';' + ')')

def evalRule(rule):
    print("Evaluating Rule")

    #ruleFile_path = "test.rules"
    #ruleFile = open(ruleFile_path, 'w+')
    #print(rule)
    #ruleFile.write(rule_to_string(rule))
    #ruleFile.close()
    #subprocess.Popen(["sudo", "suricata", "-c", "suricata.yaml", "-S", "test.rules", "-i", "wlp2s0"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.Popen(["sh", "test.sh"])

    

keywords = []

for key in icmp_keywords:
    colon = ':'
    if (key == "itype"):
        max_keyword_val = 255
    elif (key == "icode"):
        max_keyword_val = 255
        colon = random.choice([':', ':>'])
    else:
        max_keyword_val = 65535

    keywords.append((str(key), colon, random.randint(0, max_keyword_val)))

for i in range(0, random.randint(1, len(icmp_keywords))):
    while 1:
        keyword = random.choice(keywords)
        
        if keyword not in rule_options:
            rule_options.append(keyword)
            break
            

#print(rule_options)

new_rule = Rule(rule_action, rule_header, rule_message, rule_options, rule_sid)
#print(new_rule)

creator.create("Fitness", base.Fitness, weights=(1.0,))
creator.create("Individual", list, fitness=creator.Fitness)

toolbox = base.Toolbox()

test_dict = []

toolbox.register("keyword", random.choice, keywords)
toolbox.register("individual", tools.initRepeat, creator.Individual, toolbox.keyword, n=random.randint(1, len(icmp_keywords)))
toolbox.register("population", tools.initRepeat, list, toolbox.individual)
toolbox.register("evaluate", evalRule)

individual = toolbox.individual()

pop = toolbox.population(n=1)
toolbox.evaluate(individual)

#print(*pop, sep='\n')