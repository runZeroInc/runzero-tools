#!/bin/bash

SERVER=$1

if [ "$1" == "" ]; then
    echo "usage: deploy.sh [server-name]"
    exit 1
fi

set -x

export GOOS=linux
export GOARCH=amd64
go build -o rumble-dns || exit

# Ubuntu systemd must be disabled to run this
#   sudo systemctl disable systemd-resolved.service
#   sudo systemctl stop systemd-resolved

ssh root@${SERVER} 'rm -f /usr/local/bin/rumble-dns' && \
scp ./rumble-dns root@${SERVER}:/usr/local/bin/rumble-dns && \
scp ./rumble-dns.service root@${SERVER}:/lib/systemd/system/rumble-dns.service && \
ssh root@${SERVER} 'chmod 755 /usr/local/bin/rumble-dns; systemctl daemon-reload; systemctl enable rumble-dns.service; systemctl restart rumble-dns'

