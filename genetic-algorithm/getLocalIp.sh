#!/bin/bash 

ip route get 8.8.4.4 | head -1 | awk '{print $7}'
