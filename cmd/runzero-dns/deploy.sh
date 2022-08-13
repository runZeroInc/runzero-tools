#!/bin/bash

SERVER=$1

if [ "$1" == "" ]; then
    echo "usage: deploy.sh [server-name]"
    exit 1
fi

set -x

export GOOS=linux
export GOARCH=amd64
go build -o runzero-dns || exit

# Ubuntu systemd must be disabled to run this
#   sudo systemctl disable systemd-resolved.service
#   sudo systemctl stop systemd-resolved

ssh root@${SERVER} 'rm -f /usr/local/bin/runzero-dns' && \
scp ./runzero-dns root@${SERVER}:/usr/local/bin/runzero-dns && \
scp ./runzero-dns.service root@${SERVER}:/lib/systemd/system/runzero-dns.service && \
ssh root@${SERVER} 'chmod 755 /usr/local/bin/runzero-dns; systemctl daemon-reload; systemctl enable runzero-dns.service; systemctl restart runzero-dns'

