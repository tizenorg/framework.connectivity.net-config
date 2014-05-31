#!/bin/sh

#--------------------------------------
#   network
#--------------------------------------

export DISPLAY=:0.0
NETWORK_DEBUG=$1/network

/bin/mkdir -p ${NETWORK_DEBUG}

/sbin/ifconfig > ${NETWORK_DEBUG}/ifconfig
/bin/netstat -na > ${NETWORK_DEBUG}/netstat
/sbin/route -n > ${NETWORK_DEBUG}/route
/bin/cat /etc/resolv.conf > ${NETWORK_DEBUG}/resolv.conf
/usr/bin/vconftool get memory/dnet >> ${NETWORK_DEBUG}/status
/usr/bin/vconftool get memory/wifi >> ${NETWORK_DEBUG}/status
/usr/bin/vconftool get file/private/wifi >> ${NETWORK_DEBUG}/status
/usr/bin/vconftool get db/wifi >> ${NETWORK_DEBUG}/status
/sbin/ifconfig -a > ${NETWORK_DEBUG}/ifconfig
