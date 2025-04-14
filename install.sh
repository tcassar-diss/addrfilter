#!/usr/bin/env bash

set -euo pipefail

log() { echo -e "\033[1;34m[INFO]\033[0m $*"; }
error() { echo -e "\033[1;31m[ERROR]\033[0m $*" >&2; }

BINARY_NAME="addrfilter"
BUILD_PATH="./bin/$BINARY_NAME"
INSTALL_PATH="/usr/local/bin/$BINARY_NAME"

log "Building $BINARY_NAME..."
make -j

log "Installing to $INSTALL_PATH..."
sudo install -m 755 "$BUILD_PATH" "$INSTALL_PATH"

log "Build + install complete. Test with:"
echo "  sudo $BINARY_NAME --help ..."
