#!/bin/sh

if [ $# -ne 1 ]
then
    echo "version !!!"
    exit 1
fi
FILELIST="zruijie runruijie install Readme.txt"
ARCH=`uname -m`
VER=$1
TARFILE=zruijie4gzhu_bin_$VER\_$ARCH.tar.gz

make clean
make
tar cvfz $TARFILE $FILELIST
echo "Pack Done.$TARFILE"
