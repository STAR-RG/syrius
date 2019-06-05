# nids-rule-learner
=======================================================================

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
    
    
#### Malign
##### - [Hulk DOS Tool:](https://github.com/grafov/hulk)
    To install:
    $ git clone  https://github.com/grafov/hulk
    
    To run (example):
    $ hulk -site http://example.com/test/ 2>/dev/null
    
#### - [DDOSIM](https://sourceforge.net/projects/ddosim/)
    Download file from https://sourceforge.net/projects/ddosim/
    To install:
    $ tar -xzf ddosim-0.x.tar.gz
    $ cd ddosim-0.x
    $ ./configure
    $ make
    $ make install
    
    To run (example):
    $ ./ddosim -d 192.168.0.1 -p 80
    $ ./ddosim -k NETWORK_ADDRESS - p 80        
