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

#include <glib.h>
#include <gio/gio.h>
#include <glib-object.h>

#ifdef __cplusplus
extern "C" {
#endif

#define DBUS_REPLY_TIMEOUT		(120 * 1000)
#define NETCONFIG_DBUS_REPLY_TIMEOUT	(10 * 1000)
#define DBUS_INTERFACE_PROPERTIES	"org.freedesktop.DBus.Properties"

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
#define CONNMAN_ETHERNET_SERVICE_PROFILE_PREFIX	CONNMAN_PATH "/service/ethernet_"
#define CONNMAN_BLUETOOTH_SERVICE_PROFILE_PREFIX \
											CONNMAN_PATH "/service/bluetooth_"

#define CONNMAN_CELLULAR_TECHNOLOGY_PREFIX	CONNMAN_PATH "/technology/cellular"
#define CONNMAN_WIFI_TECHNOLOGY_PREFIX		CONNMAN_PATH "/technology/wifi"
#define CONNMAN_ETHERNET_TECHNOLOGY_PREFIX	CONNMAN_PATH "/technology/ethernet"
#define CONNMAN_BLUETOOTH_TECHNOLOGY_PREFIX	CONNMAN_PATH "/technology/bluetooth"

#define NETCONFIG_WIFI_INTERFACE		"net.netconfig.wifi"
#define NETCONFIG_WIFI_PATH			"/net/netconfig/wifi"
#define NETCONFIG_NETWORK_STATE_PATH		"/net/netconfig/network"
#define NETCONFIG_NETWORK_STATISTICS_PATH	"/net/netconfig/network_statistics"
#define NETCONFIG_NETWORK_PATH			"/net/netconfig/network"
#define NETCONFIG_NETWORK_INTERFACE		"net.netconfig.network"

#define DBUS_PATH_MAX_BUFLEN		512
#define DBUS_STATE_MAX_BUFLEN		64

typedef enum {
	NETCONFIG_DBUS_RESULT_GET_BGSCAN_MODE,
	NETCONFIG_DBUS_RESULT_DEFAULT_TECHNOLOGY,
} netconfig_dbus_result_type;

typedef void (*got_name_cb)(void);

GDBusObjectManagerServer	*netdbus_get_wifi_manager(void);
GDBusObjectManagerServer	*netdbus_get_state_manager(void);
GDBusObjectManagerServer	*netdbus_get_statistics_manager(void);

GDBusConnection				*netdbus_get_connection(void);
GCancellable				*netdbus_get_cancellable(void);
void netconfig_gdbus_pending_call_ref(void);
void netconfig_gdbus_pending_call_unref(void);
int netconfig_create_gdbus_call(GDBusConnection *conn);

gboolean netconfig_is_cellular_internet_profile(const char *profile);
gboolean netconfig_is_cellular_profile(const char *profile);
gboolean netconfig_is_wifi_profile(const char *profile);
gboolean netconfig_is_ethernet_profile(const char *profile);
gboolean netconfig_is_bluetooth_profile(const char *profile);

gboolean netconfig_invoke_dbus_method_nonblock(const char *dest, const char *path,
		const char *interface_name, const char *method, GVariant *params,
		GAsyncReadyCallback notify_func);
GVariant *netconfig_invoke_dbus_method(const char *dest, const char *path,
		const char *interface_name, const char *method,
		GVariant *params);

int		setup_gdbus(got_name_cb cb);
void	cleanup_gdbus(void);

#ifdef __cplusplus
}
#endif

#endif /* __NETCONFIG_NETDBUS_H__ */
