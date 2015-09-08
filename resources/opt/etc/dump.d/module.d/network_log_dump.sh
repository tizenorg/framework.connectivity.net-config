#!/bin/sh

#--------------------------------------
#   network
#--------------------------------------

export DISPLAY=:0.0
NETWORK_ORG=/opt/usr/data/network
NETWORK_DEBUG=$1/network

/bin/mkdir -p ${NETWORK_DEBUG}

/sbin/ifconfig > ${NETWORK_DEBUG}/ifconfig
/bin/netstat -na > ${NETWORK_DEBUG}/netstat
/sbin/route -n > ${NETWORK_DEBUG}/route
/bin/cat /proc/net/wireless > ${NETWORK_DEBUG}/wireless
/bin/cat /etc/resolv.conf > ${NETWORK_DEBUG}/resolv.conf
/usr/bin/vconftool get memory/dnet >> ${NETWORK_DEBUG}/status
/usr/bin/vconftool get memory/wifi >> ${NETWORK_DEBUG}/status
/usr/bin/vconftool get file/private/wifi >> ${NETWORK_DEBUG}/status
/usr/bin/vconftool get db/wifi >> ${NETWORK_DEBUG}/status
/sbin/ifconfig -a > ${NETWORK_DEBUG}/ifconfig
/bin/mv ${NETWORK_ORG}/tcpdump*.pcap $1/../
/bin/tar -czf ${NETWORK_DEBUG}/network.tar.gz -C ${NETWORK_ORG} .
