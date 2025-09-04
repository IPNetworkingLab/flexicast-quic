#!/bin/bash

if [ $APP_FILE -eq 1 ] ; then
    APP_ARGS=--stay-open
else
    APP_ARGS="--video /shared"
fi

RUST_LOG=trace fc-recv-file-transfer -l 0.0.0.0 https://$FC_SRC_IP:$FC_SRC_PORT/data.txt --output-prefix /shared --flow-control $FC_FLOWCONTROL $FLEXICAST $APP_ARGS