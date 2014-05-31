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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "log.h"
#include "netdbus.h"
#include "netconfig.h"

#define NETCONFIG_DBUS_REPLY_TIMEOUT (10 * 1000)

#define DBUS_PARAM_TYPE_STRING		"string"
#define DBUS_PARAM_TYPE_INT16		"int16"
#define DBUS_PARAM_TYPE_UINT16		"uint16"
#define DBUS_PARAM_TYPE_INT32		"int32"
#define DBUS_PARAM_TYPE_UINT32		"uint32"
#define DBUS_PARAM_TYPE_INT64		"int64"
#define DBUS_PARAM_TYPE_UINT64		"uint64"
#define DBUS_PARAM_TYPE_DOUBLE		"double"
#define DBUS_PARAM_TYPE_BYTE		"byte"
#define DBUS_PARAM_TYPE_BOOLEAN		"boolean"
#define DBUS_PARAM_TYPE_OBJECT_PATH	"objpath"
#define DBUS_PARAM_TYPE_VARIANT		"variant"
#define DBUS_PARAM_TYPE_ARRAY		"array"


static gboolean __netconfig_dbus_append_param_variant(
		DBusMessageIter *iter, char *type, char *param)
{
	DBusMessageIter value, array;
	char *args = NULL, *ch = NULL;
	dbus_bool_t b_value = FALSE;

	if (strcmp(type, DBUS_PARAM_TYPE_STRING) == 0) {
		dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT,
				DBUS_TYPE_STRING_AS_STRING, &value);

		dbus_message_iter_append_basic(&value, DBUS_TYPE_STRING, &param);

		dbus_message_iter_close_container(iter, &value);
	} else if (strcmp(type, DBUS_PARAM_TYPE_BOOLEAN) == 0) {
		if (strcmp(param, "true") == 0) {
			b_value = TRUE;
			dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT,
					DBUS_TYPE_BOOLEAN_AS_STRING, &value);
			dbus_message_iter_append_basic(&value,
					DBUS_TYPE_BOOLEAN, &b_value);
			dbus_message_iter_close_container(iter, &value);
		} else if (strcmp(param, "false") == 0) {
			b_value = FALSE;
			dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT,
					DBUS_TYPE_BOOLEAN_AS_STRING, &value);
			dbus_message_iter_append_basic(&value,
					DBUS_TYPE_BOOLEAN, &b_value);
			dbus_message_iter_close_container(iter, &value);
		} else {
			ERR("Error!!! Expected \"true\" or"
				"\"false\" instead of \"%s\"", ch);
			return FALSE;
		}
	} else if (strcmp(type, DBUS_PARAM_TYPE_OBJECT_PATH) == 0) {
		dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT,
				DBUS_TYPE_OBJECT_PATH_AS_STRING, &value);

		dbus_message_iter_append_basic(&value, DBUS_TYPE_OBJECT_PATH, &param);

		dbus_message_iter_close_container(iter, &value);
	} else if (strcmp(type, DBUS_PARAM_TYPE_ARRAY) == 0) {
		args = param;
		ch = strchr(args, ':');
		if (ch == NULL) {
			ERR("Error!!! Invalid data format[\"%s\"]", args);
			return FALSE;
		}
		*ch = 0; ch++;

		if (strcmp(args, DBUS_PARAM_TYPE_STRING) == 0) {
			dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT,
					DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_STRING_AS_STRING,
					&value);

			dbus_message_iter_open_container(&value, DBUS_TYPE_ARRAY,
					DBUS_TYPE_STRING_AS_STRING, &array);

			dbus_message_iter_append_basic(&array, DBUS_TYPE_STRING, &ch);

			dbus_message_iter_close_container(&value, &array);

			dbus_message_iter_close_container(iter, &value);
		} else if (strcmp(args, DBUS_PARAM_TYPE_OBJECT_PATH) == 0) {
			dbus_message_iter_open_container(iter, DBUS_TYPE_VARIANT,
					DBUS_TYPE_ARRAY_AS_STRING DBUS_TYPE_OBJECT_PATH_AS_STRING,
					&value);

			dbus_message_iter_open_container(&value, DBUS_TYPE_ARRAY,
					DBUS_TYPE_OBJECT_PATH_AS_STRING, &array);

			dbus_message_iter_append_basic(&array, DBUS_TYPE_OBJECT_PATH, &ch);

			dbus_message_iter_close_container(&value, &array);

			dbus_message_iter_close_container(iter, &value);
		} else {
			ERR("Error!!! Not supported data format[\"%s\"]", args);
			return FALSE;
		}
	} else {
		ERR("Error!!! Not supported data format[\"%s\"]", args);
		return FALSE;
	}

	return TRUE;
}

static gboolean __netconfig_dbus_append_param(
		DBusMessage *message, char *param_array[])
{
	int count = 0;
	dbus_uint32_t uint32 = 0;
	DBusMessageIter iter;
	char *args = NULL, *ch = NULL;

	if (param_array == NULL)
		return TRUE;

	dbus_message_iter_init_append(message, &iter);

	while (param_array[count] != NULL) {
		args = param_array[count];
		DBG("parameter %d - [%s]", count, param_array[count]);

		ch = strchr(args, ':');
		if (ch == NULL) {
			ERR("Error!!! Invalid parameter[\"%s\"]\n", args);
			return FALSE;
		}
		*ch = 0; ch++;

		if (strcmp(args, DBUS_PARAM_TYPE_STRING) == 0) {
			dbus_message_iter_append_basic(&iter, DBUS_TYPE_STRING, &ch);
		} else if (strcmp(args, DBUS_PARAM_TYPE_UINT32) == 0) {
			uint32 = strtoul(ch, NULL, 0);
			dbus_message_iter_append_basic(&iter, DBUS_TYPE_UINT32, &uint32);
		} else if (strcmp(args, DBUS_PARAM_TYPE_VARIANT) == 0) {
			args = ch;
			ch = strchr(args, ':');
			if (ch == NULL) {
				ERR("Error!!! Invalid data format[\"%s\"]\n", args);
				return FALSE;
			}
			*ch = 0; ch++;

			if (__netconfig_dbus_append_param_variant(&iter, args, ch) != TRUE)
				return FALSE;

		} else if (strcmp(args, DBUS_PARAM_TYPE_OBJECT_PATH) == 0) {
			dbus_message_iter_append_basic(&iter, DBUS_TYPE_OBJECT_PATH, &ch);
		} else {
			ERR("Error!!! Not supported data format[\"%s\"]", args);
			return FALSE;
		}

		count++;
	}

	return TRUE;
}

gboolean netconfig_dbus_get_basic_params_string(DBusMessage *message,
		char **key, int type, void *value)
{
	DBusMessageIter iter, iter_variant;

	dbus_message_iter_init(message, &iter);
	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_STRING) {
		DBG("Argument type %d", dbus_message_iter_get_arg_type(&iter));
		return FALSE;
	}

	dbus_message_iter_get_basic(&iter, key);

	if (value == NULL)
		return TRUE;

	dbus_message_iter_next(&iter);
	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_VARIANT) {
		DBG("Argument type %d", dbus_message_iter_get_arg_type(&iter));
		return TRUE;
	}

	dbus_message_iter_recurse(&iter, &iter_variant);
	if (dbus_message_iter_get_arg_type(&iter_variant) != type)
		return FALSE;

	dbus_message_iter_get_basic(&iter_variant, value);

	return TRUE;
}

gboolean netconfig_dbus_get_basic_params_array(DBusMessage *message,
		char **key, void **value)
{
	DBusMessageIter args, dict, entry, variant;
	int type = 0;

	if (key == NULL)
		return FALSE;

	/* read parameters */
	if (dbus_message_iter_init(message, &args) == FALSE) {
		DBG("Message does not have parameters");
		return FALSE;
	}

	if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_ARRAY) {
		DBG("Argument type %d", dbus_message_iter_get_arg_type(&args));
		return FALSE;
	}

	dbus_message_iter_recurse(&args, &dict);

	if (dbus_message_iter_get_arg_type(&dict) != DBUS_TYPE_DICT_ENTRY) {
		DBG("Argument type %d", dbus_message_iter_get_arg_type(&dict));
		return FALSE;
	}

	dbus_message_iter_recurse(&dict, &entry);

	if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING) {
		DBG("Argument type %d", dbus_message_iter_get_arg_type(&entry));
		return FALSE;
	}

	dbus_message_iter_get_basic(&entry, key);

	if (value == NULL)
		return TRUE;

	dbus_message_iter_next(&entry);

	if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_VARIANT) {
		DBG("Argument type %d", dbus_message_iter_get_arg_type(&entry));
		return TRUE;
	}

	dbus_message_iter_recurse(&entry, &variant);

	type = dbus_message_iter_get_arg_type(&variant);
	if (type == DBUS_TYPE_STRING)
		dbus_message_iter_get_basic(&variant, value);
	else if (type == DBUS_TYPE_BYTE || type == DBUS_TYPE_BOOLEAN ||
			type == DBUS_TYPE_INT16 || type == DBUS_TYPE_UINT16 ||
			type == DBUS_TYPE_INT32 || type == DBUS_TYPE_UINT32 ||
			type == DBUS_TYPE_DOUBLE)
		dbus_message_iter_get_basic(&variant, *value);
	else
		DBG("Argument type %d", type);

	return TRUE;
}

gboolean netconfig_is_cellular_profile(const char *profile)
{
	if (profile == NULL)
		return FALSE;

	return g_str_has_prefix(profile, CONNMAN_CELLULAR_SERVICE_PROFILE_PREFIX);
}

gboolean netconfig_is_wifi_profile(const char *profile)
{
	if (profile == NULL)
		return FALSE;

	return g_str_has_prefix(profile, CONNMAN_WIFI_SERVICE_PROFILE_PREFIX);
}

gboolean netconfig_is_ethernet_profile(const char *profile)
{
	if (profile == NULL)
		return FALSE;

	return g_str_has_prefix(profile, CONNMAN_ETHERNET_SERVICE_PROFILE_PREFIX);
}

gboolean netconfig_is_bluetooth_profile(const char *profile)
{
	if (profile == NULL)
		return FALSE;

	return g_str_has_prefix(profile, CONNMAN_BLUETOOTH_SERVICE_PROFILE_PREFIX);
}

gboolean netconfig_invoke_dbus_method_nonblock(
		const char *dest, const char *path,
		const char *interface_name, const char *method, char *param_array[],
		DBusPendingCallNotifyFunction notify_func)
{
	dbus_bool_t result;
	DBusPendingCall *call;
	DBusMessage *message = NULL;
	DBusConnection *connection = NULL;

	DBG("[DBUS Async] %s %s %s", interface_name, method, path);

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (connection == NULL) {
		ERR("Failed to get system bus");

		return FALSE;
	}

	message = dbus_message_new_method_call(dest, path, interface_name, method);
	if (message == NULL) {
		ERR("Failed DBus method call");

		dbus_connection_unref(connection);

		return FALSE;
	}

	if (__netconfig_dbus_append_param(message, param_array) == FALSE) {
		ERR("Failed to append DBus params");

		dbus_message_unref(message);
		dbus_connection_unref(connection);

		return FALSE;
	}

	result = dbus_connection_send_with_reply(connection, message, &call,
			NETCONFIG_DBUS_REPLY_TIMEOUT);

	if (result != TRUE || call == NULL) {
		ERR("dbus_connection_send_with_reply() failed.");

		dbus_message_unref(message);
		dbus_connection_unref(connection);

		return FALSE;
	}

	if (notify_func == NULL)
		dbus_pending_call_cancel(call);
	else
		dbus_pending_call_set_notify(call, notify_func, NULL, NULL);

	dbus_message_unref(message);
	dbus_connection_unref(connection);

	return TRUE;
}

DBusMessage *netconfig_invoke_dbus_method(const char *dest, const char *path,
		const char *interface_name, const char *method, char *param_array[])
{
	DBusError error;
	DBusConnection *conn = NULL;
	DBusMessage *reply = NULL;
	DBusMessage *message = NULL;

	DBG("[DBUS Sync] %s %s %s", interface_name, method, path);

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (conn == NULL) {
		ERR("Failed to get system bus");

		return NULL;
	}

	message = dbus_message_new_method_call(dest, path, interface_name, method);
	if (message == NULL) {
		ERR("Error!!! Failed to GetProperties");

		dbus_connection_unref(conn);

		return NULL;
	}

	if (__netconfig_dbus_append_param(message, param_array) == FALSE) {
		ERR("Error!!! __netconfig_dbus_append_param() failed");

		dbus_message_unref(message);
		dbus_connection_unref(conn);

		return NULL;
	}

	dbus_error_init(&error);

	reply =	dbus_connection_send_with_reply_and_block(conn, message,
			NETCONFIG_DBUS_REPLY_TIMEOUT, &error);

	if (reply == NULL) {
		if (dbus_error_is_set(&error) == TRUE) {
			ERR("Error!!! dbus_connection_send_with_reply_and_block() failed. "
					"DBus error [%s: %s]", error.name, error.message);

			dbus_error_free(&error);
		} else
			ERR("Error!!! Failed to get properties");

		dbus_message_unref(message);
		dbus_connection_unref(conn);

		return NULL;
	}

	dbus_message_unref(message);
	dbus_connection_unref(conn);

	return reply;
}

char *netconfig_wifi_get_connected_service_name(DBusMessage *message)
{
	int is_connected = 0;
	char *essid_name = NULL;
	DBusMessageIter iter, array;

	dbus_message_iter_init(message, &iter);
	dbus_message_iter_recurse(&iter, &array);

	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, string;
		const char *key = NULL;

		dbus_message_iter_recurse(&array, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		if (g_str_equal(key, "State") == TRUE && is_connected == 0) {
			dbus_message_iter_next(&entry);
			dbus_message_iter_recurse(&entry, &string);

			if (dbus_message_iter_get_arg_type(&string) == DBUS_TYPE_STRING) {
				dbus_message_iter_get_basic(&string, &key);

				if (g_str_equal(key, "ready") == TRUE ||
						g_str_equal(key, "online") == TRUE)
					is_connected = 1;
			}
		} else if (g_str_equal(key, "Name") == TRUE) {
			dbus_message_iter_next(&entry);
			dbus_message_iter_recurse(&entry, &string);

			if (dbus_message_iter_get_arg_type(&string) == DBUS_TYPE_STRING) {
				dbus_message_iter_get_basic(&string, &key);

				essid_name = (char *)g_strdup(key);
			}
		}

		dbus_message_iter_next(&array);
	}

	if (is_connected == 1 && essid_name != NULL)
		return essid_name;

	if (essid_name != NULL)
		g_free(essid_name);

	return NULL;
}

DBusGConnection *netconfig_setup_dbus(void)
{
	DBusGConnection* connection = NULL;
	GError *error = NULL;
	DBusGProxy *proxy;
	guint rv = 0;

	connection = dbus_g_bus_get(DBUS_BUS_SYSTEM, &error);
	if (connection == NULL) {
		ERR("Fail to get DBus(%s)", error->message);
		g_error_free(error);

		return connection;
	}

	INFO("Successfully get system DBus connection(%p)", connection);

	proxy = dbus_g_proxy_new_for_name(connection, "org.freedesktop.DBus",
			"/org/freedesktop/DBus",
			"org.freedesktop.DBus");

	if (!dbus_g_proxy_call(proxy, "RequestName", &error,
			G_TYPE_STRING, NETCONFIG_SERVICE, G_TYPE_UINT, 0,
			G_TYPE_INVALID, G_TYPE_UINT, &rv,
			G_TYPE_INVALID)) {
		ERR("Failed to acquire service(%s) error(%s)",
				NETCONFIG_SERVICE, error->message);
		g_error_free(error);

		dbus_g_connection_unref(connection);

		return NULL;
	}

	if (rv != DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER) {
		ERR("Service name is already in use");

		dbus_g_connection_unref(connection);

		return NULL;
	}

	return connection;
}
