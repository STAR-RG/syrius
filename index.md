<p style="text-align: center;">
  
               
```                                                                              
   d888888o.  `8.`8888.      ,8' 8 888888888o.    8 8888 8 8888      88    d888888o.   
 .`8888:' `88. `8.`8888.    ,8'  8 8888    `88.   8 8888 8 8888      88  .`8888:' `88. 
 8.`8888.   Y8  `8.`8888.  ,8'   8 8888     `88   8 8888 8 8888      88  8.`8888.   Y8 
 `8.`8888.       `8.`8888.,8'    8 8888     ,88   8 8888 8 8888      88  `8.`8888.     
  `8.`8888.       `8.`88888'     8 8888.   ,88'   8 8888 8 8888      88   `8.`8888.    
   `8.`8888.       `8. 8888      8 888888888P'    8 8888 8 8888      88    `8.`8888.   
    `8.`8888.       `8 8888      8 8888`8b        8 8888 8 8888      88     `8.`8888.  
8b   `8.`8888.       8 8888      8 8888 `8b.      8 8888 ` 8888     ,8P 8b   `8.`8888. 
`8b.  ;8.`8888       8 8888      8 8888   `8b.    8 8888   8888   ,d8P  `8b.  ;8.`8888 
 `Y8888P ,88P'       8 8888      8 8888     `88.  8 8888    `Y88888P'    `Y8888P ,88P' 
 ```


 Syrius is a a novel approach to synthesize rules for rule-based NIDS
 
 </p>
                                                                                     
# Requirements

Syrius uses a number of open source projects to work properly:

* [Suricata] (and all its dependencies) - A free and open source network threat detection engine.
* [pyshark] - Python wrapper for tshark
* [PyYAML] -  PyYAML is a YAML parser and emitter for Python.

## Installation

We recommend running installSuricata.sh as it automatically installs Suricata's dependencies, Suricata itself and Syrius dependencies.

## Inputs

Syrius requires two .pcap files and one .rules file to run correctly:

- attack.pcap -> contains the isolated malicious packet(s)
- benign.pcap -> contains benign packets
- rules.rules -> contains the rule set used in the ranking step
- add image showing the inputs

# Usage

```sh
Usage:
$ python3 syrius.py [OPTIONS]

  Synthesis of Rules for Intrusion Detectors
  
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

## Tests

This repository includes a few examples of attacks from multiple sources, and a benign one from [tcpreplay].

We also provide the results obtained by running them, as well as other experiments.

As the attack examples are already in the required folder and format, you can run it yourself, for example:

```sh
$ python3 syrius.py -a "Datasets/adaptor.pcap"
```

# WIP

- WIP

   [pyshark]: <https://github.com/KimiNewt/pyshark>
   [Suricata]: <https://suricata-ids.org/>
   [PyYAML]: <https://pypi.org/project/PyYAML/>
   [tcpreplay]: <https://tcpreplay.appneta.com/wiki/captures.html>
