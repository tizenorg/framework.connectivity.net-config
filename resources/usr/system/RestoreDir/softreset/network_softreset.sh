#!/bin/sh

#Keep network config files
pkg -k /var/lib/connman
pkg -k /var/lib/wifi
pkg -k /var/lib/net-config

#Keep network vconf for the last state of wifi
pkg -v file/private/wifi/last_power_state
pkg -v file/private/wifi/wifi_off_by_airplane
pkg -v file/private/wifi/wifi_off_by_emergency
pkg -v db/private/wifi/wearable_wifi_use

