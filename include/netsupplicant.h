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

#ifndef __NETCONFIG_NETSUPPLICANT_H__
#define __NETCONFIG_NETSUPPLICANT_H__

#include "netdbus.h"

#ifdef __cplusplus
extern "C" {
#endif

#define	 WIFI_IFNAME					"wlan0"

#define SUPPLICANT_SERVICE				"fi.w1.wpa_supplicant1"
#define SUPPLICANT_INTERFACE			"fi.w1.wpa_supplicant1"
#define SUPPLICANT_IFACE_INTERFACE		SUPPLICANT_INTERFACE ".Interface"
#define SUPPLICANT_IFACE_BSS			SUPPLICANT_INTERFACE ".BSS"
#define SUPPLICANT_IFACE_WPS			SUPPLICANT_INTERFACE ".Interface.WPS"
#define SUPPLICANT_PATH					"/fi/w1/wpa_supplicant1"

struct dbus_input_arguments {
	int type;
	void *data;
};

/* Returns Supplicant interface
 * Do not free the returned interface */
const char *netconfig_wifi_get_supplicant_interface(void);

GList *setup_input_args(GList *list, struct dbus_input_arguments *items);
GVariant *netconfig_supplicant_invoke_dbus_method(const char *dest, const char *path,
		const char *interface_name, const char *method,
		GVariant *params);
gboolean netconfig_supplicant_invoke_dbus_method_nonblock(const char *dest,
		const char *path, const char *interface_name,
		const char *method, GVariant *params,
		GAsyncReadyCallback notify_func);
GVariant *netconfig_supplicant_invoke_dbus_interface_property_get(const char *interface,
			const char *key);
gboolean netconfig_supplicant_invoke_dbus_interface_property_set(const char *interface,
			const char *key, GVariant *message,
			GAsyncReadyCallback notify_func);

#ifdef __cplusplus
}
#endif

#endif /* __NETCONFIG_NETSUPPLICANT_H__ */
