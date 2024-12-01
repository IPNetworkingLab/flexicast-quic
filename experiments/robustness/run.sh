#!/bin/bash

sudo -E \
    ../venv/bin/npf-compare\
    local:Multicast --test mobility.npf\
    --variables "NB_CLIENTS={20}"\
    "MC_FAILURE={1}" FAILURE=130 FAILURE_DURATION=15000 FAILURE_INTERVAL=5000\
    DURATION=180\
    TCPDUMP_GRANULARITY=1 RTP_SINK=1 FAILURE_PROBA=0.5\
    "FB_DELAY={50,100,150}" "PB_DELAY={50,100,150}"\
    ENABLE_CWND=1\
    --config n_runs=1 --show-cmd\
    --single-output output.csv\
    --no-graph --force-retest
