FROM ubuntu:18.04
LABEL maintainer="rui@computer.org"

ENV VER=4.1.7

RUN apt-get install software-properties-common
RUN apt-add-repository universe
RUN apt update
RUN apt -y install software-properties-common 
RUN apt -y install python2.7 python3-pip tshark wireshark git libpcre3 libpcre3-dbg libpcre3-dev build-essential autoconf automake libtool libpcap-dev libnet1-dev libyaml-0-2 libyaml-dev zlib1g zlib1g-dev libcap-ng-dev libcap-ng0 make libmagic-dev libjansson-dev libjansson4 pkg-config libnspr4-dev libnss3-dev liblz4-dev rustc cargo libhtp-dev

RUN pip3 install pyshark

RUN wget "http://www.openinfosecfoundation.org/download/suricata-$VER.tar.gz" 
RUN tar -xvzf "suricata-$VER.tar.gz"

RUN cd suricata-$VER/libhtp

RUN git clone https://github.com/OISF/libhtp.git

RUN cd libhtp
RUN ./autogen.sh
RUN ./configure
RUN make
RUN make install

RUN cd ../../suricata-update
RUN git clone https://github.com/OISF/suricata-update.git
RUN cd suricata-update
RUN python2 setup.py build
RUN python2 setup.py install

RUN cd ../..

RUN pip install PyYAML

RUN ./configure && make && sudo make install-full

RUN ldconfig
