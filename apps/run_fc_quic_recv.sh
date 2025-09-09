#!/bin/bash

check_app() {
    case $1 in
        rss )
            echo "RSS application"
            APP_ARGS="--stay-open --transfer-kind file,file,/shared"
            ;;
        
        bbb )
            echo "Big Buck Bunny application"
            APP_ARGS="--transfer-kind stream,hls,/shared"
            ;;
        
        ssim )
            echo "SSIM application"
            APP_ARGS="--transfer-kind stream,rtp,${RTPSINK}"
            ;;

        *)
            echo "Unsupported application"
            exit 1
            ;;
    esac
}

check_app $APP_KIND

RUST_LOG=$RUST_LOG_LEVEL fc-recv-file-transfer -l 0.0.0.0 https://$FC_SRC_IP:$FC_SRC_PORT/data.txt --flow-control $FC_FLOWCONTROL $FLEXICAST $APP_ARGS --transport-feedback
