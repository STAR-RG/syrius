# nids-rule-learner
========================================================================

### - Traffic Generator tools

#### Benign
##### - [ApacheBench](https://httpd.apache.org/docs/2.4/programs/ab.html): 
	To install:
    $ sudo apt install apache2-utils
    
    To run (example):
    $ ab -n 1000 -c 10 -k www.google.com/
    
    
##### - [HTStress](https://github.com/LucasAugustp/htstress):
	To install:
    $ git clone https://github.com/LucasAugustp/htstress
    $ cd htstress
    $ ./build.sh
    
    To run (example):
    $ ./htstress -n 1000 -c 10 -t 4 www.google.com
    
    
