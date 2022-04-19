#!/bin/bash

mkdir -p openssl_build

build_dir=$(pwd)/openssl_build

echo $build_dir

pushd ./openssl_1.1.1

./config --prefix=$build_dir --openssldir=$build_dir
make -j6
make install

popd

