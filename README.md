# Syrius

Syrius is a a novel approach to synthesize rules for rule-based NIDS

  - Image

### Requirements

Syrius uses a number of open source projects to work properly:

* [Suricata] (and all its dependencies) - A free and open source network threat detection engine.
* [pyshark] - Python wrapper for tshark
* [PyYAML] -  PyYAML is a YAML parser and emitter for Python.

### Installation

We recommend running the installSuricata.sh as it automatically installs Suricata's dependencies, Suricata itself and Syrius dependencies.

After that, just clone this repository and run syrius/syrius.py.

### Usage

Syrius requires two .pcap files to run correctly, one containing the isolated malicious packet and another containing benign packets. They must be stored in specific folders:

- syrius/Datasets/[ATTACK].pcap
- syrius/[BENIGN].pcap

Where [ATTACK] must be the same name used as parameter later, and [BENIGN] must be named benign.pcap. This repository includes a few examples of attacks from multiple sources, and a benign one from [tcpreplay].

- add image showing the .pcap

After that you only need to run Syrius and wait for the results:

```sh
Usage:
$ python3 syrius.py [ATTACK]
```

It will initially show the seed rule, and other information such as protocol.

After each iteration of the rule synthesis, Syrius will show the number of rules generated up to that point. When all iterations are done, it will print the best ranked rule, as well as generate a results_[ATTACK].csv with all plausible rules ordered by fitness.


TIP: If you already know the protocol of the attack, we recommend using a filtered benign.pcap with only packets of that protocol. This will make the testing faster.

### WIP

- WIP

   [pyshark]: <https://github.com/KimiNewt/pyshark>
   [Suricata]: <https://suricata-ids.org/>
   [PyYAML]: <https://pypi.org/project/PyYAML/>
   [tcpreplay]: <https://tcpreplay.appneta.com/wiki/captures.html>
