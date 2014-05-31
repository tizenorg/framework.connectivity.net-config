/*
 * Network Configuration Module
 *
 * Copyright (c) 2012-2013 Samsung Electronics Co., Ltd. All rights reserved.
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

#ifdef __cplusplus
extern "C" {
#endif

#include <glib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>

#define SUPPLICANT_SERVICE				"fi.w1.wpa_supplicant1"
#define SUPPLICANT_INTERFACE			"fi.w1.wpa_supplicant1"
#define SUPPLICANT_PATH					"/fi/w1/wpa_supplicant1"
#define SUPPLICANT_GLOBAL_INTERFACE		"org.freedesktop.DBus.Properties"

struct dbus_input_arguments {
	int type;
	void *data;
};

gboolean netconfig_wifi_get_ifname(char **ifname);
gboolean netconfig_wifi_get_supplicant_interface(char **path);
DBusMessage *netconfig_supplicant_invoke_dbus_method(const char *dest,
		DBusConnection *connection,
		const char *path, const char *interface_name,
		const char *method, GList *args);

#ifdef __cplusplus
}
#endif

#endif /* __NETCONFIG_NETSUPPLICANT_H__ */
