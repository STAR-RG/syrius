# Syrius

Syrius is a a novel approach to synthesize rules for rule-based NIDS

  - Image

# Requirements

Syrius uses a number of open source projects to work properly:

* [Suricata] (and all its dependencies) - A free and open source network threat detection engine.
* [pyshark] - Python wrapper for tshark
* [PyYAML] -  PyYAML is a YAML parser and emitter for Python.

# Installation

We recommend running installSuricata.sh as it automatically installs Suricata's dependencies, Suricata itself and Syrius dependencies.

# Usage

Syrius requires two .pcap files to run correctly, and must be stored in specific folders:

- syrius/Datasets/[ATTACK].pcap -> contains the isolated malicious packet(s)
- syrius/benign.pcap            -> contains benign packets

Where [ATTACK] must be the same name used as parameter. 

- add image showing the .pcap

After that you only need to run Syrius:

```sh
Usage:
$ python3 syrius.py [ATTACK]
```

As Syrius runs, it will show the seed rule, and total plausible rules created up to that iteration.

 At the end, it will generate a results_[ATTACK].csv with all plausible rules ordered by fitness.


TIP: If you already know the protocol of the attack, we recommend using a filtered benign.pcap with only packets of that protocol. This will make the testing faster.

# Tests

This repository includes a few examples of attacks from multiple sources, and a benign one from [tcpreplay].

We also provide the results obtained by running them, as well as other experiments.

As the attack examples are already in the required folder and format, you can run it yourself, for example:

```sh
Usage:
$ python3 syrius.py adaptor
```

# WIP

- WIP

   [pyshark]: <https://github.com/KimiNewt/pyshark>
   [Suricata]: <https://suricata-ids.org/>
   [PyYAML]: <https://pypi.org/project/PyYAML/>
   [tcpreplay]: <https://tcpreplay.appneta.com/wiki/captures.html>
