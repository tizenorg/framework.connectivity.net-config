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

#ifndef __NETCONFIG_NETDBUS_H__
#define __NETCONFIG_NETDBUS_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <glib.h>
#include <dbus/dbus.h>
#include <dbus/dbus-glib.h>

#define NETCONFIG_SERVICE				"net.netconfig"

#define CONNMAN_SERVICE					"net.connman"
#define CONNMAN_PATH					"/net/connman"

#define CONNMAN_CLOCK_INTERFACE			CONNMAN_SERVICE ".Clock"
#define CONNMAN_ERROR_INTERFACE			CONNMAN_SERVICE ".Error"
#define CONNMAN_MANAGER_INTERFACE		CONNMAN_SERVICE ".Manager"
#define CONNMAN_SERVICE_INTERFACE		CONNMAN_SERVICE ".Service"
#define CONNMAN_TECHNOLOGY_INTERFACE	CONNMAN_SERVICE ".Technology"
#define CONNMAN_MANAGER_PATH			"/"

#define CONNMAN_CELLULAR_SERVICE_PROFILE_PREFIX	CONNMAN_PATH "/service/cellular_"
#define CONNMAN_WIFI_SERVICE_PROFILE_PREFIX		CONNMAN_PATH "/service/wifi_"

#define CONNMAN_CELLULAR_TECHNOLOGY_PREFIX		CONNMAN_PATH "/technology/cellular"
#define CONNMAN_WIFI_TECHNOLOGY_PREFIX			CONNMAN_PATH "/technology/wifi"

#define NETCONFIG_WIFI_INTERFACE		"net.netconfig.wifi"
#define NETCONFIG_WIFI_PATH				"/net/netconfig/wifi"

#define DBUS_PATH_MAX_BUFLEN		512
#define DBUS_STATE_MAX_BUFLEN		64

typedef enum {
	NETCONFIG_DBUS_RESULT_GET_BGSCAN_MODE,
	NETCONFIG_DBUS_RESULT_DEFAULT_TECHNOLOGY,
} netconfig_dbus_result_type;

gboolean netconfig_is_cellular_internet_profile(const char *profile);
gboolean netconfig_is_cellular_profile(const char *profile);
gboolean netconfig_is_wifi_profile(const char *profile);

gboolean netconfig_invoke_dbus_method_nonblock(
		const char *dest, const char *path,
		const char *interface_name, const char *method, char *param_array[],
		DBusPendingCallNotifyFunction notify_func);
DBusMessage *netconfig_invoke_dbus_method(const char *dest, const char *path,
		const char *interface_name, const char *method, char *param_array[]);

gboolean netconfig_dbus_get_basic_params_string(DBusMessage *message,
		char **key, int type, void *value);
gboolean netconfig_dbus_get_basic_params_array(DBusMessage *message,
		const char *key, void **value);

DBusGConnection *netconfig_setup_dbus(void);

#ifdef __cplusplus
}
#endif

#endif /* __NETCONFIG_NETDBUS_H__ */
