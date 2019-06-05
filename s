#!/bin/bash

###
## Tools
###

### Benign traffic
## install apache-bench, tool to generate benign HTTP traffic
sudo apt install apache2-utils

# install HTStress, another tool to generate benign HTTP traffic
git clone https://github.com/LucasAugustp/htstress
(cd htstress;
 ./build.sh
)

### Malicious traffic
# install 
git clone  https://github.com/grafov/hulk