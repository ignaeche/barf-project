#! /bin/bash

temp_dir=dependencies

# Install basic stuff
#sudo apt-get install -y binutils-dev build-essential g++ nasm
#sudo apt-get install -y python-setuptools python-dev
#sudo apt-get install -y graphviz xdot

# Create temp directory
rm -rf $temp_dir
mkdir $temp_dir
cd $temp_dir

# Install Capstone Core
wget -nc "https://github.com/aquynh/capstone/archive/master.zip"
unzip -o master.zip
cd capstone-master/
sed -i.bak 's/PREFIX ?= \/usr/PREFIX ?= ~\/.local\/lib\/python2.7\/site-packages\/capstone/g' Makefile
sed -i.bak 's/LIBDIRARCH ?= lib/LIBDIRARCH ?= \./g' Makefile
./make.sh install

# Install Capstone Python Bindings
cd bindings/python/
rm ~/.local/lib/python2.7/site-packages/capstone/*.pyc -f
rm ~/.local/lib/python2.7/site-packages/capstone/*.py -f
python setup.py install --user
cd ../../..

mkdir z3
cd z3
wget -nc 'http://download-codeplex.sec.s-msft.com/Download/SourceControlFileDownload.ashx?ProjectName=z3&changeSetId=89c1785b7322' -O z3.zip
unzip -o z3.zip
# Install z3
autoconf
./configure --prefix=$(echo ~/.local/usr) --with-python=/usr/bin/python2
python scripts/mk_make.py --nodotnet
cd build/
make
cp z3 ~/.local/bin/
cd ../..

# Install CVC4 dependencies
#sudo apt-get install -y libboost-all-dev libantlr3c-dev libgmp-dev

# Install CVC4
#wget http://cvc4.cs.nyu.edu/builds/src/cvc4-1.4.tar.gz
#tar xfz cvc4-1.4.tar.gz
#rm -f cvc4-1.4.tar.gz
#cd cvc4-1.4/
#./configure
#make
#sudo make install
#cd ..

# Remove temp directory
#cd ..
# rm -rf $temp_dir

# Install BARF
python setup.py develop --user
