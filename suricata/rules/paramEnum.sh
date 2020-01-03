#!/bin/bash

paramList=($(sudo suricata --list-keywords))

for param in "${paramList[@]}";
do
    if [ $param != "=====Supported" ] && [ $param != "keywords=====" ] && [ $param != '-' ] && [ $param != "lua" ] && [ $param != "(not" ] && [ $param != "built-in)" ] && [ $param != "msg" ] && [ $param != "rev" ] && [ $param != "sid" ] && [ $param != "reference" ] && [ $param != "metadata" ] && [ $param != "target" ] && [ $param != "priority" ] && [ $param != "gid" ] && [ $param != "classtype" ] 
    then
        echo $(grep -Ro "\b$param:" $1 | wc -l) $param
    fi
done