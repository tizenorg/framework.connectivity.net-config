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

#include "log.h"
#include "netdbus.h"
#include "netsupplicant.h"

#define DBUS_OBJECT_PATH_MAX			150

const char *netconfig_wifi_get_supplicant_interface(void)
{
	GVariant *message = NULL;
	GVariant *params = NULL;
	gchar *path = NULL;
	static char obj_path[DBUS_OBJECT_PATH_MAX] = { '\0', };

	if (obj_path[0] != '\0')
		return (const char *)obj_path;

	params = g_variant_new("(s)", WIFI_IFNAME);

	message = netconfig_supplicant_invoke_dbus_method(
			SUPPLICANT_SERVICE, SUPPLICANT_PATH,
			SUPPLICANT_INTERFACE, "GetInterface", params);

	if (message == NULL) {
		ERR("Failed to get object path");
		return NULL;
	}

	g_variant_get(message, "(o)", &path);

	g_strlcpy(obj_path, path, DBUS_OBJECT_PATH_MAX);

	if (path)
		g_free(path);
	g_variant_unref(message);

	return (const char *)obj_path;
}

GVariant *netconfig_supplicant_invoke_dbus_method(const char *dest, const char *path,
		const char *interface_name, const char *method, GVariant *params)
{
	GError *error = NULL;
	GVariant *reply = NULL;
	GDBusConnection *connection = NULL;

	INFO("[DBUS Sync] %s %s %s", interface_name, method, path);

	connection = netdbus_get_connection();
	if (connection == NULL) {
		ERR("Failed to get GDBus Connection");
		return NULL;
	}

	reply = g_dbus_connection_call_sync(
			connection,
			dest,
			path,
			interface_name,
			method,
			params,
			NULL,
			G_DBUS_CALL_FLAGS_NONE,
			NETCONFIG_DBUS_REPLY_TIMEOUT,
			netdbus_get_cancellable(),
			&error);

	if (reply == NULL) {
		if (error != NULL) {
			ERR("g_dbus_connection_call_sync() failed"
						"error [%d: %s]", error->code, error->message);
			g_error_free(error);
		} else {
			ERR("g_dbus_connection_call_sync() failed");
		}

		return NULL;
	}

	return reply;
}

gboolean netconfig_supplicant_invoke_dbus_method_nonblock(const char *dest,
		const char *path, const char *interface_name,
		const char *method, GVariant *params,
		GAsyncReadyCallback notify_func)
{
	GDBusConnection *connection = NULL;

	INFO("[DBUS Async] %s %s %s", interface_name, method, path);

	connection = netdbus_get_connection();
	if (connection == NULL) {
		DBG("Failed to get GDBusconnection");
		return FALSE;
	}

	g_dbus_connection_call(connection,
			dest,
			path,
			interface_name,
			method,
			params,
			NULL,
			G_DBUS_CALL_FLAGS_NONE,
			NETCONFIG_DBUS_REPLY_TIMEOUT,
			netdbus_get_cancellable(),
			(GAsyncReadyCallback) notify_func,
			NULL);

	return TRUE;
}

GVariant *netconfig_supplicant_invoke_dbus_interface_property_get(const char *interface,
			const char *key)
{
	GVariant *params = NULL;
	GVariant *reply = NULL;
	const char *path;

	ERR("[GDBUS] property_get : %s", key);

	path = netconfig_wifi_get_supplicant_interface();
	if (path == NULL) {
		DBG("Failed to get wpa_supplicant DBus path");
		return NULL;
	}

	params = g_variant_new("(ss)", interface, key);

	reply = netconfig_supplicant_invoke_dbus_method(SUPPLICANT_SERVICE,
			path,
			DBUS_INTERFACE_PROPERTIES,
			"Get",
			params);

	if (reply == NULL) {
		ERR("netconfig_supplicant_invoke_dbus_method() failed.");
		return NULL;
	}

	return reply;
}

gboolean netconfig_supplicant_invoke_dbus_interface_property_set(const char *interface,
			const char *key, GVariant *var,
			GAsyncReadyCallback notify_func)
{
	gboolean result = FALSE;
	GVariant *message = NULL;
	const char *path;

	DBG("[DBUS] property_set : %s", key);

	path = netconfig_wifi_get_supplicant_interface();
	if (path == NULL) {
		ERR("Failed to get wpa_supplicant DBus path");
		return result;
	}

	message = g_variant_new("(ssv)", interface, key, var);
	result = netconfig_invoke_dbus_method_nonblock(SUPPLICANT_SERVICE,
			path,
			DBUS_INTERFACE_PROPERTIES,
			"Set",
			message,
			notify_func);

	if (result == FALSE) {
		ERR("dbus_connection_send_with_reply() failed");

		return result;
	}

	return result;
}
