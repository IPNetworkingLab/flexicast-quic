#!/bin/bash

RUST_LOG=trace fc-recv-file-transfer -l 0.0.0.0 https://$AMT_IP:$FC_SRC_PORT/data.txt --output-prefix /shared --stay-open --flow-control $FC_FLOWCONTROL $FLEXICAST