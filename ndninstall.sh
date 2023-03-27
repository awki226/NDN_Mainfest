#!/bin/bash
sudo yum install -y gcc-c++ pkgconf-pkg-config python3 boost-devel openssl-devel sqlite-devel
sudo yum config-manager --enable powertools
sudo yum install -y doxygen graphviz python3-pip
pip3 install -y --user sphinx sphinxcontrib-doxylink
git clone https://github.com/named-data/ndn-cxx.git
cd ndn-cxx
export LD_LIBRARY_PATH='/usr/local/lib64'
#May have to use devtoolset-8 for centos 7
./waf configure --without-pch
./waf
sudo ./waf install
sudo ldconfig
cd ..
git clone --recursive https://github.com/named-data/NFD.git
cd NFD
#May have to use devtoolset-8 for centos 7
./waf configure --without-pch
./waf 
sudo ./waf install
sudo ldconfig
sudo cp /usr/local/etc/ndn/nfd.conf.sample /usr/local/etc/ndn/nfd.conf
sudo vi /usr/local/etc/ndn/nfd.conf
