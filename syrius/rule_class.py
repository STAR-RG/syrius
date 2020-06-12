import math
from functools import partial

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

    """def calculateFitness(self):
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
    """
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


def sortRules(file_dir, w):
    with open(file_dir, "r") as all_rules:
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
    all_rules_len = len(all_rules_list)

    #print("all rules len: ", all_rules_len)

    #print("weights: ", str(w))
    all_rules_list = sorted(all_rules_list, key=partial(callGetFitness, weights=w))
    # exit()
    for x, rule in enumerate(all_rules_list):
        if rule.sid == 1099019:
            golden_rule_pos = all_rules_list.index(rule)
        else:
            rule.sid = x+1

    current_pos = all_rules_len-golden_rule_pos

    return current_pos

def readRawRule(file_name):
    with open(file_name, 'r') as reader:
        lines = reader.readlines()
        #print(len(lines))
        return lines


def readAllRawRules():
    print("reading all raw rules")
    attacks_list = ["adaptor", "coldfusion", "htaccess", "idq", "issadmin", "system", "script", "cron", "inc", "jsp", "teardrop"]
    all_rules = []
    for atk in attacks_list:
        #print("reading", atk)
        file_name = "all_rules_raw_"+str(atk)+".out"
        all_rules.append(readRawRule(file_name))

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
                             
    return all_rules_list
 

def sortMultiplesAttacks(w, *args):
    print(w)
    all_rules_list = list(args)
    attacks_list = ["adaptor", "coldfusion", "htaccess", "idq", "issadmin", "system", "script", "cron", "inc", "jsp", "teardrop"]
    current_pos = [0] * len(all_rules_list)
    golden_rule_pos = [0] * len(all_rules_list)
    all_rules_len = []
    all_pos_sum = 0
    for i in range(len(all_rules_list)):
        all_rules_len.append(len(all_rules_list[i]))
        all_rules_list[i] = sorted(all_rules_list[i], key=partial(callGetFitness, weights=w))
        
        found_golden_rule = False
        for x, rule in enumerate(all_rules_list[i]):
            if rule.sid == 1099019:
                golden_rule_pos[i] = all_rules_list[i].index(rule)
                found_golden_rule = True
            else:
                rule.sid = x+1
        if found_golden_rule:
            current_pos[i] = all_rules_len[i]-golden_rule_pos[i]
        else:
            current_pos[i] = all_rules_len[i]
        all_pos_sum += current_pos[i]
        # print("current pos", i, ": ", current_pos[i])
        # print("best pos: ", best_pos[i])

        
    for i in range(len(current_pos)):
       print(attacks_list[i]+':'+str(current_pos[i])+' ', end=' ')
    print()
    print("soma:", sum(current_pos))
    return sum(current_pos)


