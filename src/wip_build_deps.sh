#!/bin/bash

mkdir -p build/openssl_build

ossl_build_dir=$(pwd)/build/openssl_build

echo $ossl_build_dir

pushd ./openssl_1.1.1

./config --prefix=$ossl_build_dir --openssldir=$ossl_build_dir
make -j6
make install

popd

pushd build

echo "#define SO_IMPLEMENTATION #include "../simpleopenssl/include/simpleopenssl.h" >> so.cpp



