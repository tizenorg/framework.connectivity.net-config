/*
 * Network Configuration Module
 *
 * Copyright (c) 2000 - 2012 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#ifndef __NETCONFIG_WIFI_SSID_SCAN_H__
#define __NETCONFIG_WIFI_SSID_SCAN_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "wifi.h"

enum netconfig_wifi_security {
	WIFI_SECURITY_UNKNOWN = 0x00,
	WIFI_SECURITY_NONE = 0x01,
	WIFI_SECURITY_WEP = 0x02,
	WIFI_SECURITY_PSK = 0x03,
	WIFI_SECURITY_IEEE8021X = 0x04,
};

gboolean netconfig_wifi_get_ssid_scan_state(void);

void netconfig_wifi_notify_ssid_scan_done(DBusMessage *message);
void netconfig_wifi_bss_added(DBusMessage *message);

gboolean netconfig_iface_wifi_request_specific_scan(NetconfigWifi *wifi,
			gchar *ssid, GError **error);

#ifdef __cplusplus
}
#endif

#endif /* __NETCONFIG_WIFI_SSID_SCAN_H__ */
