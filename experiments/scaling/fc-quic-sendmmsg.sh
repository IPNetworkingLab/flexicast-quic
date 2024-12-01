#!/bin/bash

npf-compare local:Multicast --test ./scaling.npf --cluster\
    server=<ssh-addr node-2>:/tmp/,nic=2,nfs=0\
    proxy=<ssh-addr node-1>:/tmp/,nic=2,nfs=0\
    client=<ssh-addr node-0>:/tmp/,nic=2,nfs=0\
    client=<ssh-addr node-3>:/tmp/,nic=2,nfs=0\
    client=<ssh-addr node-4>:/tmp/,nic=2,nfs=0\
    client=<ssh-addr node-5>:/tmp/,nic=2,nfs=0\
    --cluster-autosave --variables DEBUG=0 "TIMER={0}"\
    "NB_CLIENTS={1,25,50,100,150,200,250}"\
    "PURE_UDP={0}"\
    CPUSUM=0 "PACING=0" "ACK_ELICIT={0}" "NTHREADS={20}"\
    "INTHROUGHPUT={150}"\
    "MULTICAST={1}"\
    SENDMMSG=1\
    --show-files --show-cmd --single-output results-fcquic-sendmmsg.csv --config n_runs=1 --variables V=3 --force-retest