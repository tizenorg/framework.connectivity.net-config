#!/bin/sh

# Make directory for backup
/bin/mkdir -p /opt/system/softreset_preserved/network/
cd /opt/system/softreset_preserved/network/

# Move network config files
/bin/mv /var/lib/connman /var/lib/wifi /var/lib/net-config .
