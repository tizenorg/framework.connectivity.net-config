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

#include <vconf.h>
#include <vconf-keys.h>
#include <aul.h>

#include "wifi.h"
#include "log.h"
#include "util.h"
#include "netdbus.h"
#include "neterror.h"
#include "emulator.h"
#include "wifi-state.h"
#include "network-state.h"

#define NETCONFIG_NETWORK_STATE_PATH	"/net/netconfig/network"
#define ROUTE_EXEC_PATH			"/sbin/route"

#define PROP_DEFAULT		FALSE
#define PROP_DEFAULT_STR   NULL


gboolean netconfig_iface_network_state_add_route(
		NetconfigNetworkState *master,
		gchar *ip_addr, gchar *netmask,
		gchar *interface, gboolean *result, GError **error);

gboolean netconfig_iface_network_state_remove_route(
		NetconfigNetworkState *master,
		gchar *ip_addr, gchar *netmask,
		gchar *interface, gboolean *result, GError **error);

#include "netconfig-iface-network-state-glue.h"

enum {
	PROP_O,
	PROP_NETWORK_STATE_CONN,
	PROP_NETWORK_STATE_PATH,
};

struct NetconfigNetworkStateClass {
	GObjectClass parent;
};

struct NetconfigNetworkState {
	GObject parent;

	DBusGConnection *conn;
	gchar *path;
};

G_DEFINE_TYPE(NetconfigNetworkState, netconfig_network_state, G_TYPE_OBJECT);


static void __netconfig_network_state_gobject_get_property(GObject *object,
		guint prop_id, GValue *value, GParamSpec *pspec)
{
	return;
}

static void __netconfig_network_state_gobject_set_property(GObject *object,
		guint prop_id, const GValue *value, GParamSpec *pspec)
{
	NetconfigNetworkState *network_state = NETCONFIG_NETWORK_STATE(object);

	switch (prop_id) {
	case PROP_NETWORK_STATE_CONN:
	{
		network_state->conn = g_value_get_boxed(value);
		INFO("network_state(%p) set conn(%p)", network_state, network_state->conn);
		break;
	}

	case PROP_NETWORK_STATE_PATH:
	{
		if (network_state->path)
			g_free(network_state->path);

		network_state->path = g_value_dup_string(value);
		INFO("network_state(%p) path(%s)", network_state, network_state->path);

		break;
	}

	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
	}
}

static void netconfig_network_state_init(NetconfigNetworkState *network_state)
{
	DBG("network_state initialize");

	network_state->conn = NULL;
	network_state->path = g_strdup(PROP_DEFAULT_STR);
}

static void netconfig_network_state_class_init(NetconfigNetworkStateClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS(klass);

	DBG("class initialize");

	object_class->get_property = __netconfig_network_state_gobject_get_property;
	object_class->set_property = __netconfig_network_state_gobject_set_property;

	/* DBus register */
	dbus_g_object_type_install_info(NETCONFIG_TYPE_NETWORK_STATE,
			&dbus_glib_netconfig_iface_network_state_object_info);

	/* property */
	g_object_class_install_property(object_class, PROP_NETWORK_STATE_CONN,
			g_param_spec_boxed("conn", "CONNECTION", "DBus connection",
					DBUS_TYPE_G_CONNECTION,
					G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property(object_class, PROP_NETWORK_STATE_PATH,
			g_param_spec_string("path", "Path", "Object path",
					PROP_DEFAULT_STR,
					G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}

struct netconfig_default_connection {
	char *profile;
	char *ifname;
	char *ipaddress;
	char *proxy;
	char *essid;
};

static struct netconfig_default_connection
				netconfig_default_connection_info;

static void __netconfig_pop_3g_alert_syspoppup(void)
{
	int rv = 0;
	bundle *b = NULL;
	int wifi_ug_state = 0;

	vconf_get_int(VCONFKEY_WIFI_UG_RUN_STATE, &wifi_ug_state);
	if (wifi_ug_state == VCONFKEY_WIFI_UG_RUN_STATE_ON_FOREGROUND)
		return;

	b = bundle_create();

	bundle_add(b, "_SYSPOPUP_TITLE_", "Cellular connection popup");
	bundle_add(b, "_SYSPOPUP_TYPE_", "notification");
	bundle_add(b, "_SYSPOPUP_CONTENT_", "connected");

	DBG("Launch 3G alert network popup");
	rv = aul_launch_app("org.tizen.net-popup", b);

	bundle_free(b);
}

static gboolean __netconfig_is_connected(const char *profile)
{
	gboolean is_connected = FALSE;
	DBusMessage *message = NULL;
	DBusMessageIter iter, array;

	if (profile == NULL)
		return FALSE;

	message = netconfig_invoke_dbus_method(CONNMAN_SERVICE, profile,
			CONNMAN_SERVICE_INTERFACE, "GetProperties", NULL);
	if (message == NULL) {
		ERR("Failed to get service properties");
		return is_connected;
	}

	if (dbus_message_get_type(message) == DBUS_MESSAGE_TYPE_ERROR) {
		const char *ptr = dbus_message_get_error_name(message);
		ERR("Error!!! Error message received [%s]", ptr);
		goto done;
	}

	dbus_message_iter_init(message, &iter);
	dbus_message_iter_recurse(&iter, &array);

	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, string;
		const char *key = NULL;

		dbus_message_iter_recurse(&array, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		if (g_str_equal(key, "State") == TRUE) {
			dbus_message_iter_next(&entry);
			dbus_message_iter_recurse(&entry, &string);

			if (dbus_message_iter_get_arg_type(&string) == DBUS_TYPE_STRING) {
				dbus_message_iter_get_basic(&string, &key);

				if (g_str_equal(key, "ready") == TRUE ||
						g_str_equal(key, "online") == TRUE) {
					is_connected = TRUE;

					break;
				}
			}
		}

		dbus_message_iter_next(&array);
	}

done:
	if (message != NULL)
		dbus_message_unref(message);

	return is_connected;
}

static char *__netconfig_get_default_profile(void)
{
	DBusMessage *message = NULL;
	GSList *service_profiles = NULL;
	GSList *list = NULL;
	DBusMessageIter iter, dict;
	char *default_profile = NULL;

	message = netconfig_invoke_dbus_method(CONNMAN_SERVICE,
			CONNMAN_MANAGER_PATH, CONNMAN_MANAGER_INTERFACE,
			"GetServices", NULL);
	if (message == NULL) {
		ERR("Failed to get profiles");
		return NULL;
	}

	dbus_message_iter_init(message, &iter);
	dbus_message_iter_recurse(&iter, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_STRUCT) {
		DBusMessageIter entry;
		const char *object_path = NULL;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &object_path);

		if (object_path)
			service_profiles = g_slist_append(
						service_profiles,
						g_strdup(object_path));

		dbus_message_iter_next(&dict);
	}

	for (list = service_profiles; list != NULL; list = list->next) {
		char *profile_path = list->data;

		if (__netconfig_is_connected((const char *)profile_path) == TRUE) {
			default_profile = g_strdup(profile_path);
			break;
		}
	}

	g_slist_free(service_profiles);

	dbus_message_unref(message);

	return default_profile;
}

static void __netconfig_get_default_connection_info(const char *profile)
{
	DBusMessage *message = NULL;
	DBusMessageIter iter, array;

	message = netconfig_invoke_dbus_method(CONNMAN_SERVICE, profile,
			CONNMAN_SERVICE_INTERFACE, "GetProperties", NULL);
	if (message == NULL) {
		ERR("Failed to get service properties");
		return;
	}

	if (dbus_message_get_type(message) == DBUS_MESSAGE_TYPE_ERROR) {
		const char *ptr = dbus_message_get_error_name(message);
		ERR("Error!!! Error message received [%s]", ptr);
		goto done;
	}

	dbus_message_iter_init(message, &iter);
	dbus_message_iter_recurse(&iter, &array);

	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, variant, string, iter1, iter2, iter3;
		const char *key = NULL, *value = NULL;

		dbus_message_iter_recurse(&array, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		if (g_str_equal(key, "Name") == TRUE &&
				netconfig_is_wifi_profile(profile) == TRUE) {
			dbus_message_iter_next(&entry);
			dbus_message_iter_recurse(&entry, &string);

			if (dbus_message_iter_get_arg_type(&string) == DBUS_TYPE_STRING) {
				dbus_message_iter_get_basic(&string, &value);

				netconfig_default_connection_info.essid = g_strdup(value);
			}
		} else if (g_str_equal(key, "Ethernet") == TRUE) {
			dbus_message_iter_next(&entry);
			dbus_message_iter_recurse(&entry, &variant);
			dbus_message_iter_recurse(&variant, &iter1);

			while (dbus_message_iter_get_arg_type(&iter1)
					== DBUS_TYPE_DICT_ENTRY) {
				dbus_message_iter_recurse(&iter1, &iter2);
				dbus_message_iter_get_basic(&iter2, &key);

				if (g_str_equal(key, "Interface") == TRUE) {
					dbus_message_iter_next(&iter2);
					dbus_message_iter_recurse(&iter2, &iter3);
					dbus_message_iter_get_basic(&iter3, &value);

					netconfig_default_connection_info.ifname = g_strdup(value);
				}

				dbus_message_iter_next(&iter1);
			}
		} else if (g_str_equal(key, "IPv4") == TRUE) {
			dbus_message_iter_next(&entry);
			dbus_message_iter_recurse(&entry, &variant);
			dbus_message_iter_recurse(&variant, &iter1);

			while (dbus_message_iter_get_arg_type(&iter1)
					== DBUS_TYPE_DICT_ENTRY) {
				dbus_message_iter_recurse(&iter1, &iter2);
				dbus_message_iter_get_basic(&iter2, &key);

				if (g_str_equal(key, "Address") == TRUE) {
					dbus_message_iter_next(&iter2);
					dbus_message_iter_recurse(&iter2, &iter3);
					dbus_message_iter_get_basic(&iter3, &value);

					netconfig_default_connection_info.ipaddress = g_strdup(value);
				}

				dbus_message_iter_next(&iter1);
			}
		} else if (g_str_equal(key, "IPv6") == TRUE) {
			dbus_message_iter_next(&entry);
			dbus_message_iter_recurse(&entry, &variant);
			dbus_message_iter_recurse(&variant, &iter1);

			while (dbus_message_iter_get_arg_type(&iter1)
					== DBUS_TYPE_DICT_ENTRY) {
				dbus_message_iter_recurse(&iter1, &iter2);
				dbus_message_iter_get_basic(&iter2, &key);

				if (g_str_equal(key, "Address") == TRUE) {
					dbus_message_iter_next(&iter2);
					dbus_message_iter_recurse(&iter2, &iter3);
					dbus_message_iter_get_basic(&iter3, &value);

					netconfig_default_connection_info.ipaddress = g_strdup(value);
				}

				dbus_message_iter_next(&iter1);
			}
		} else if (g_str_equal(key, "Proxy") == TRUE) {
			dbus_message_iter_next(&entry);
			dbus_message_iter_recurse(&entry, &variant);
			dbus_message_iter_recurse(&variant, &iter1);

			while (dbus_message_iter_get_arg_type(&iter1)
					== DBUS_TYPE_DICT_ENTRY) {
				DBusMessageIter iter4;

				dbus_message_iter_recurse(&iter1, &iter2);
				dbus_message_iter_get_basic(&iter2, &key);

				if (g_str_equal(key, "Servers") == TRUE) {
					dbus_message_iter_next(&iter2);
					dbus_message_iter_recurse(&iter2, &iter3);
					if (dbus_message_iter_get_arg_type(&iter3)
							!= DBUS_TYPE_ARRAY)
						break;

					dbus_message_iter_recurse(&iter3, &iter4);
					if (dbus_message_iter_get_arg_type(&iter4)
							!= DBUS_TYPE_STRING)
						break;

					dbus_message_iter_get_basic(&iter4, &value);
					if (value != NULL && (strlen(value) > 0))
						netconfig_default_connection_info.proxy = g_strdup(value);

				} else if (g_str_equal(key, "Method") == TRUE) {
					dbus_message_iter_next(&iter2);
					dbus_message_iter_recurse(&iter2, &iter3);
					if (dbus_message_iter_get_arg_type(&iter3)
							!= DBUS_TYPE_STRING)
						break;

					dbus_message_iter_get_basic(&iter3, &value);
					if (g_strcmp0(value, "direct") == 0) {
						g_free(netconfig_default_connection_info.proxy);
						netconfig_default_connection_info.proxy = NULL;

						break;
					}
				}

				dbus_message_iter_next(&iter1);
			}
		}

		dbus_message_iter_next(&array);
	}

done:
	if (message != NULL)
		dbus_message_unref(message);
}

static void __netconfig_update_default_connection_info(void)
{
	int old_network_status = 0;
	const char *profile = netconfig_get_default_profile();
	const char *ip_addr = netconfig_get_default_ipaddress();
	const char *proxy_addr = netconfig_get_default_proxy();

	if (netconfig_emulator_is_emulated() == TRUE)
		return;

	if (profile == NULL)
		DBG("Reset network state configuration");
	else
		DBG("%s: ip(%s) proxy(%s)", profile, ip_addr, proxy_addr);

	vconf_get_int(VCONFKEY_NETWORK_STATUS, &old_network_status);

	if (profile == NULL && old_network_status != VCONFKEY_NETWORK_OFF) {
		vconf_set_int(VCONFKEY_NETWORK_STATUS, VCONFKEY_NETWORK_OFF);

		vconf_set_str(VCONFKEY_NETWORK_IP, "");
		vconf_set_str(VCONFKEY_NETWORK_PROXY, "");

		vconf_set_int(VCONFKEY_NETWORK_CONFIGURATION_CHANGE_IND, 0);

		DBG("Successfully clear IP and PROXY up");
	} else if (profile != NULL) {
		char *old_ip = vconf_get_str(VCONFKEY_NETWORK_IP);
		char *old_proxy = vconf_get_str(VCONFKEY_NETWORK_PROXY);

		if (netconfig_is_wifi_profile(profile) == TRUE) {
			vconf_set_int(VCONFKEY_NETWORK_STATUS, VCONFKEY_NETWORK_WIFI);
		} else if (netconfig_is_cellular_profile(profile) == TRUE) {
			vconf_set_int(VCONFKEY_NETWORK_STATUS, VCONFKEY_NETWORK_CELLULAR);

			if (old_network_status != VCONFKEY_NETWORK_CELLULAR)
				__netconfig_pop_3g_alert_syspoppup();
		} else if (netconfig_is_ethernet_profile(profile) == TRUE) {
			vconf_set_int(VCONFKEY_NETWORK_STATUS, VCONFKEY_NETWORK_ETHERNET);
		} else if (netconfig_is_bluetooth_profile(profile) == TRUE) {
			vconf_set_int(VCONFKEY_NETWORK_STATUS, VCONFKEY_NETWORK_BLUETOOTH);
		} else {
			vconf_set_int(VCONFKEY_NETWORK_STATUS, VCONFKEY_NETWORK_OFF);
		}

		if (g_strcmp0(old_ip, ip_addr) != 0) {
			if (ip_addr == NULL)
				vconf_set_str(VCONFKEY_NETWORK_IP, "");
			else
				vconf_set_str(VCONFKEY_NETWORK_IP, ip_addr);
		}

		if (g_strcmp0(old_proxy, proxy_addr) != 0) {
			if (proxy_addr == NULL)
				vconf_set_str(VCONFKEY_NETWORK_PROXY, "");
			else
				vconf_set_str(VCONFKEY_NETWORK_PROXY, proxy_addr);
		}

		vconf_set_int(VCONFKEY_NETWORK_CONFIGURATION_CHANGE_IND, 1);

		DBG("Successfully update default network configuration");
	}
}

const char *netconfig_get_default_profile(void)
{
	return netconfig_default_connection_info.profile;
}

const char *netconfig_get_default_ipaddress(void)
{
	return netconfig_default_connection_info.ipaddress;
}

const char *netconfig_get_default_proxy(void)
{
	return netconfig_default_connection_info.proxy;
}

const char *netconfig_wifi_get_connected_essid(const char *default_profile)
{
	if (default_profile == NULL)
		return NULL;

	if (netconfig_is_wifi_profile(default_profile) != TRUE)
		return NULL;

	if (g_str_equal(default_profile, netconfig_default_connection_info.profile)
			!= TRUE)
		return NULL;

	return netconfig_default_connection_info.essid;
}

void netconfig_set_default_profile(const char *profile)
{
	char *default_profile = NULL;

	/* It's automatically updated by signal-handler
	 * DO NOT update manually
	 *
	 * It is going to update default connection information
	 */
	if (netconfig_default_connection_info.profile != NULL) {
		g_free(netconfig_default_connection_info.profile);
		netconfig_default_connection_info.profile = NULL;

		g_free(netconfig_default_connection_info.ifname);
		netconfig_default_connection_info.ifname = NULL;

		g_free(netconfig_default_connection_info.ipaddress);
		netconfig_default_connection_info.ipaddress = NULL;

		g_free(netconfig_default_connection_info.proxy);
		netconfig_default_connection_info.proxy = NULL;

		if (netconfig_wifi_state_get_service_state()
				!= NETCONFIG_WIFI_CONNECTED) {
			g_free(netconfig_default_connection_info.essid);
			netconfig_default_connection_info.essid = NULL;
		}
	}

	if (profile == NULL) {
		default_profile = __netconfig_get_default_profile();
		if (default_profile == NULL) {
			__netconfig_update_default_connection_info();
			return;
		}
	}

	if (profile != NULL)
		netconfig_default_connection_info.profile = g_strdup(profile);
	else
		netconfig_default_connection_info.profile = default_profile;

	__netconfig_get_default_connection_info(
			netconfig_default_connection_info.profile);

	__netconfig_update_default_connection_info();
}

gboolean netconfig_iface_network_state_add_route(
		NetconfigNetworkState *master,
		gchar *ip_addr, gchar *netmask,
		gchar *interface, gboolean *result, GError **error)
{
	gboolean ret = FALSE;
	gboolean rv = FALSE;
	const char *path = ROUTE_EXEC_PATH;
	char *const args[] = {"route", "add",
				"-net", ip_addr,
				"netmask", netmask,
				"dev", interface,
				0};
	char *const envs[] = { NULL };

	DBG("ip_addr(%s), netmask(%s), interface(%s)", ip_addr, netmask, interface);

	if (ip_addr == NULL || netmask == NULL || interface == NULL) {
		DBG("Invalid parameter!");
		goto done;
	}

	rv = netconfig_execute_file(path, args, envs);
	if (rv != TRUE) {
		DBG("Failed to add a new route");
		goto done;
	}

	DBG("Successfully added a new route");
	ret = TRUE;

done:
	*result = ret;
	return ret;
}

gboolean netconfig_iface_network_state_remove_route(
		NetconfigNetworkState *master,
		gchar *ip_addr, gchar *netmask,
		gchar *interface, gboolean *result, GError **error)
{
	gboolean ret = FALSE;
	gboolean rv = FALSE;
	const char *path = ROUTE_EXEC_PATH;
	char *const args[] = {"route", "del",
				"-net", ip_addr,
				"netmask", netmask,
				"dev", interface,
				0};
	char *const envs[] = { NULL };

	DBG("ip_addr(%s), netmask(%s), interface(%s)", ip_addr, netmask, interface);

	if (ip_addr == NULL || netmask == NULL || interface == NULL) {
		DBG("Invalid parameter!");
		goto done;
	}

	rv = netconfig_execute_file(path, args, envs);
	if (rv != TRUE) {
		DBG("Failed to remove a new route");
		goto done;
	}

	DBG("Successfully remove a new route");
	ret = TRUE;

done:
	*result = ret;
	return ret;
}

gpointer netconfig_network_state_create_and_init(DBusGConnection *conn)
{
	GObject *object;

	g_return_val_if_fail(conn != NULL, NULL);

	object = g_object_new(NETCONFIG_TYPE_NETWORK_STATE, "conn", conn, "path",
			NETCONFIG_NETWORK_STATE_PATH, NULL);

	INFO("create network_state(%p)", object);

	dbus_g_connection_register_g_object(conn, NETCONFIG_NETWORK_STATE_PATH, object);

	INFO("network_state(%p) register DBus path(%s)", object, NETCONFIG_NETWORK_STATE_PATH);

	return object;
}
