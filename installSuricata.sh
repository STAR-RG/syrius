VER=5.0.2

sudo apt-add-repository universe
sudo apt update
sudo apt -y install software-properties-common 
sudo apt -y install python3-pip tshark wireshark git libpcre3 libpcre3-dbg libpcre3-dev build-essential autoconf automake libtool libpcap-dev libnet1-dev libyaml-0-2 libyaml-dev zlib1g zlib1g-dev libcap-ng-dev libcap-ng0 make libmagic-dev libjansson-dev libjansson4 pkg-config libnspr4-dev libnss3-dev liblz4-dev rustc cargo libhtp-dev

pip3 install pyshark

wget "http://www.openinfosecfoundation.org/download/suricata-$VER.tar.gz" 

tar -xvzf "suricata-$VER.tar.gz"

cd suricata-$VER/libhtp

git clone https://github.com/OISF/libhtp.git

cd libhtp
./autogen.sh
./configure
make
sudo make install

cd ../../suricata-update
git clone https://github.com/OISF/suricata-update.git
cd suricata-update
python setup.py build
sudo python setup.py install

cd ../..

pip install PyYAML

./configure && make && sudo make install-full

sudo ldconfig
