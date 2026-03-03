#!/bin/bash
set -e

# Start the Flexicast QUIC source
QLOGDIR="/rss_feed" RUST_LOG=trace fc-flow-file-transfer --src $FC_SRC_IP:$FC_SRC_PORT --fc-timer $fc_ack_delay --cert-path /certs -r test_server_output.txt -k server_key.txt --mc-addr $MC_IP:$MC_PORT $FLEXICAST --ctl-ack-delay 0 --fc-cwnd $FC_CCA --transfer-kind socket:/rss_feed/$RSS_SOCKET_NAME