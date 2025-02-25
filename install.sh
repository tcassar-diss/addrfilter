#!/usr/bin/env bash

log_fatal() {
    echo "$@"
    exit 1
}

if [[ -f /usr/local/bin/syso ]]; then
    echo "[INFO] cleaning old binary"
    sudo rm /usr/local/bin/addrfilter
fi

make

sudo cp ./bin/addrfilter /usr/local/bin

eval "$(/usr/local/bin/addrfilter completion bash)"
