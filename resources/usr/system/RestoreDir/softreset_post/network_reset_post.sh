#!/bin/sh

# restore network config files
/bin/rm -rf /var/lib/connman /var/lib/wifi /var/lib/net-config

/bin/mv /opt/system/softreset_preserved/network/* /var/lib/
