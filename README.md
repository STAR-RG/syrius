<p style="text-align: center;">
  
![logo](https://github.com/damorimRG/syrius/blob/gh-pages/logo.png?raw=true "Syrius")

 Syrius is a a novel approach to synthesize rules for rule-based NIDS
 
 </p>
                                                                                     
# Instalation

Git clone this repository and run installSuricata.sh:

```console
$ git clone https://github.com/damorimRG/syrius
$ cd syrius
$ chmod +x installSuricata.sh
$ ./installSuricata.sh
```
These instructions will install the following tools:

* [Suricata] (and all its dependencies) - A free and open source network threat detection engine.
* [pyshark] - Python wrapper for tshark
* [PyYAML] -  PyYAML is a YAML parser and emitter for Python.

With this you are ready to run Syrius.

# Inputs and Outputs

![inout](https://github.com/damorimRG/syrius/blob/gh-pages/InOut.png?raw=true "Input and Output")

Inputs:

- Attack Packets -> attack.pcap containing the isolated malicious packet(s).
- Benign Packets -> benign.pcap containing benign packets.
- Rules set -> rules.rules containing the rule set to be used in the ranking step.

Output:

- List of Rules -> A list of rules that isolate the attack with 100% Precision and Recall to the given attack and benign traffic. The list is ranked using heuristics based on the Rules set.

# Usage

```console
$ python3 syrius.py [OPTIONS]

  Synthesis of Rules for rule-based NIDS
  
Options:
  -attack, -a  Filename of the attack .pcap. Default: attack.pcap
  -benign, -b  Filename of the benign .pcap. Default: benign.pcap
  -rules, -r   Filename of the ruleset .rules. Default: rules.rules
  -output, -o  Filename of the output .out. Default: output.out
  -help, -h    Show this message and exit.

```

As Syrius runs, it will show the seed rule, and total plausible rules created up to that iteration.

At the end, it will generate the output with all plausible rules ordered by fitness.

TIP: If you already know the protocol of the attack, we recommend using a filtered benign.pcap with only packets of that protocol. This will make the testing faster.

# Illustrative Example

This repository includes a few examples of attacks from multiple sources, and a benign one from [tcpreplay].

We also provide the results obtained by running them, as well as other experiments.

After finishing the instalation steps above, do the following:

```console
$ cd syrius
$ python3 syrius.py -a "./Datasets/synflood.pcap" -b "./Datasets/benign.pcap" -r "./Datasets/rules.rules"
```
This will run Syrius using with the synflood attack pcap, the bigflows benign pcap from tcpreplay and the Emerging Threats rules from Suricata.

The program will show you the seed rule created, as well as the total number of rules created in each iteration.

After all iterations, the most well ranked rule will be shown to the user, and an output file "output.out" with all plausible rules ordered by ranking will be created on the default path. You can read it with any csv reader.

   [pyshark]: <https://github.com/KimiNewt/pyshark>
   [Suricata]: <https://suricata-ids.org/>
   [PyYAML]: <https://pypi.org/project/PyYAML/>
   [tcpreplay]: <https://tcpreplay.appneta.com/wiki/captures.html>
