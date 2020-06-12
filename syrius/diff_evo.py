from scipy.optimize import differential_evolution
from copy import copy
from rule_class import readAllRawRules
from rule_class import sortMultiplesAttacks
from rule_class import sortRules
import os

def get_score(fit_list, weights):
    return sum([f*w for f,w in zip(fit_list, weights)])/len(weights)

def cost(w, *args):
    print(w)
    atk_lst, idxs = args
    costs = []
    for idx, atk in zip(idxs, atk_lst):
        tmp = copy(atk)
        score = get_score(tmp[idx], w)
        del tmp[idx]
        cost = max_dif(atk, w) - score
        costs.append(cost)
    output = sum(costs)
    #print(output)
    return output


def max_dif(atk, weights):
    score_list = [get_score(fit_list, weights) for fit_list in atk]
    return max(score_list)


attacks=["adaptor", "coldfusion", "cron", "htaccess", "idq", "inc", "issadmin", "jsp", "script", "system",  "teardrop"]
#attacks=["coldfusion", "jsp", "inc"]
weights=[0.44915267, 0.10303724, 0.05363035, 0.79628946]

"""for atk in attacks:
    print(atk)
    subdir="./zenodo/table3/Table 3/all_rules_raw_"+atk+".out"
    for i in range(len(weights)):
        aux_weights = copy(weights)
        aux_weights[i] = 0   
        pos = sortRules(subdir, aux_weights)
        #print(aux_weights)
        print(pos)

exit()
"""      
"""
packets=[0, 1, 100, 10000, "all"]
attacks=["coldfusion", "jsp", "inc"]
for atk in attacks:
    atk_dir = "./zenodo/fig9/"+atk+"/"
    for pkts in packets:
        if str(pkts) != "all":
            file_name = atk_dir+"data"+str(pkts)+".txt"
        else:
            file_name = atk_dir+"data"+"100000.txt"

        with open(file_name, "w+") as writer:
            dir = atk_dir+str(pkts)+"/"
            print(dir)
            for i in ["%.2d" % n for n in range(1, 11)]:
                subdir = dir+str(i)+"/all_rules_raw_"+atk+".out"  
                pos = sortRules(subdir, weights)
                writer.write(str(pos)+'\n')

exit()
"""
atk_lst = []
for atk in attacks:
    with open(atk+'.fit', 'r') as file:
        fit_lst = [eval(line) for line in file]
        atk_lst.append(fit_lst)

idxs=[87, 5, 18, 2, 2, 49, 2, 40, 2, 3]
args = (atk_lst, idxs)

all_raw_rules = readAllRawRules()

bounds = [(0,1), (0,1), (0,1), (0,1)]
result = differential_evolution(sortMultiplesAttacks, bounds, polish=True, workers=-1, args=all_raw_rules)
print(result.x)
print(result.nit)
