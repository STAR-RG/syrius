#!/bin/bash

## generate 1000 requests from 10 different clients to www.google.com
#ab -n 1000 -c 10 -k www.google.com/

## generate benign traffic
(cd htstress;
 ./htstress -n 1000 -c 10 -t 4 www.google.com
)

## generate malicious traffic
hulk -site http://example.com/test/ 2>/dev/null
