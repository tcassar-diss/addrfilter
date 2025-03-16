#!/usr/bin/env bash

log_fatal() {
    echo "$@"
    exit 1
}

noerr() {
    if [[ $? -ne 0 ]]; then
        log "cmd failed!!"
        exit 1
    fi
}

if [[ -f /usr/local/bin/addrfilter ]]; then
    echo "[INFO] cleaning old binary"
    sudo rm /usr/local/bin/addrfilter
fi

sudo cp ./bin/addrfilter /usr/local/bin/addrfilter
noerr
echo "[INFO] installed new binary"
sudo /usr/local/bin/addrfilter completion bash | sudo tee "/etc/bash_completion.d/addrfilter" >/dev/null
noerr
source "/etc/bash_completion.d/addrfilter"
noerr
echo "[INFO] installed completions"
