#!/bin/sh

# $1 is passed by dump_service

export DISPLAY=:0.0
NETWORK_ORG=/opt/usr/data/network
NETWORK_DEBUG=$1/network

/bin/mkdir -p ${NETWORK_DEBUG}
/bin/tar -czf ${NETWORK_DEBUG}/network.tar.gz -C ${NETWORK_ORG} .
