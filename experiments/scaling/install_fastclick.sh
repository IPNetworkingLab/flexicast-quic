#!/bin/bash

git clone 

https://sigcomm-ccr:1H6Wq3BENAHz2BpMw1YZ@forge.uclouvain.be/inl/multicast-quic/fastclick.git

cd fastclick

./configure  CFLAGS="-O3" CXXFLAGS="-std=c++11 -O3" --enable-dpdk --enable-intel-cpu --disable-dynamic-linking --enable-bound-port-transfer --enable-flow --disable-task-stats --disable-cpu-load --enable-dpdk-packet --disable-clone --disable-dpdk-softqueue

make