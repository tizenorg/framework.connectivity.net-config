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

#include <vconf.h>
#include <vconf-keys.h>
#include <fcntl.h>
#include <unistd.h>
#include <aul.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>

#include "log.h"
#include "util.h"
#include "netdbus.h"
#include "neterror.h"
#include "emulator.h"
#include "wifi-state.h"
#include "wifi-power.h"
#include "network-state.h"
#include "netsupplicant.h"

/* Define TCP buffer sizes for various networks */
/* ReadMin, ReadInitial, ReadMax */ /* WriteMin, WriteInitial, WriteMax */
#define NET_TCP_BUFFERSIZE_DEFAULT_READ		"4096 87380 704512"
#define NET_TCP_BUFFERSIZE_DEFAULT_WRITE	"4096 16384 110208"
#define NET_TCP_BUFFERSIZE_WIFI_READ		"524288 1048576 2560000"
#define NET_TCP_BUFFERSIZE_WIFI_WRITE		"524288 1048576 2560000"
#define NET_TCP_BUFFERSIZE_LTE_READ			"524288 1048576 2560000"
#define NET_TCP_BUFFERSIZE_LTE_WRITE		"524288 1048576 2560000"
#define NET_TCP_BUFFERSIZE_UMTS_READ		"4094 87380 704512"
#define NET_TCP_BUFFERSIZE_UMTS_WRITE		"4096 16384 110208"
#define NET_TCP_BUFFERSIZE_HSPA_READ		"4092 87380 704512"
#define NET_TCP_BUFFERSIZE_HSPA_WRITE		"4096 16384 262144"
#define NET_TCP_BUFFERSIZE_HSDPA_READ		"4092 87380 704512"
#define NET_TCP_BUFFERSIZE_HSDPA_WRITE		"4096 16384 110208"
#define NET_TCP_BUFFERSIZE_HSUPA_READ		"4092 87380 704512"
#define NET_TCP_BUFFERSIZE_HSUPA_WRITE		"4096 16384 262144"
#define NET_TCP_BUFFERSIZE_HSPAP_READ		"4092 87380 704512"
#define NET_TCP_BUFFERSIZE_HSPAP_WRITE		"4096 16384 262144"
#define NET_TCP_BUFFERSIZE_EDGE_READ		"4093 26280 35040"
#define NET_TCP_BUFFERSIZE_EDGE_WRITE		"4096 16384 35040"
#define NET_TCP_BUFFERSIZE_GPRS_READ		"4096 30000 30000"
#define NET_TCP_BUFFERSIZE_GPRS_WRITE		"4096 8760 11680"

#define NET_TCP_BUFFERSIZE_WIFI_RMEM_MAX	"1048576"
#define NET_TCP_BUFFERSIZE_WIFI_WMEM_MAX	"2097152"
#define NET_TCP_BUFFERSIZE_LTE_RMEM_MAX		"5242880"

#define NET_TCP_BUFFERSIZE_WIFID_WMEM_MAX	"2097152"

#define NET_PROC_SYS_NET_IPV4_TCP_RMEM		"/proc/sys/net/ipv4/tcp_rmem"
#define NET_PROC_SYS_NET_IPv4_TCP_WMEM		"/proc/sys/net/ipv4/tcp_wmem"
#define NET_PROC_SYS_NET_CORE_RMEM_MAX		"/proc/sys/net/core/rmem_max"
#define NET_PROC_SYS_NET_CORE_WMEM_MAX		"/proc/sys/net/core/wmem_max"

#define ROUTE_EXEC_PATH						"/sbin/route"


#define NETCONFIG_NETWORK_STATE_PATH	"/net/netconfig/network"

#define PROP_DEFAULT		FALSE
#define PROP_DEFAULT_STR	NULL

gboolean netconfig_iface_network_state_add_route(
		NetconfigNetworkState *master,
		gchar *ip_addr, gchar *netmask,
		gchar *interface, gboolean *result, GError **error);

gboolean netconfig_iface_network_state_remove_route(
		NetconfigNetworkState *master,
		gchar *ip_addr, gchar *netmask,
		gchar *interface, gboolean *result, GError **error);

gboolean netconfig_iface_network_state_check_get_privilege();

gboolean netconfig_iface_network_state_check_profile_privilege();

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

	DBusGConnection *connection;
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
		network_state->connection = g_value_get_boxed(value);
		break;
	}

	case PROP_NETWORK_STATE_PATH:
	{
		if (network_state->path)
			g_free(network_state->path);

		network_state->path = g_value_dup_string(value);
		break;
	}

	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
	}
}

static void netconfig_network_state_init(NetconfigNetworkState *network_state)
{
	network_state->connection = NULL;
	network_state->path = g_strdup(PROP_DEFAULT_STR);
}

static void netconfig_network_state_class_init(NetconfigNetworkStateClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS(klass);

	object_class->get_property = __netconfig_network_state_gobject_get_property;
	object_class->set_property = __netconfig_network_state_gobject_set_property;

	/* DBus register */
	dbus_g_object_type_install_info(NETCONFIG_TYPE_NETWORK_STATE,
			&dbus_glib_netconfig_iface_network_state_object_info);

	/* property */
	g_object_class_install_property(object_class, PROP_NETWORK_STATE_CONN,
			g_param_spec_boxed("connection", "CONNECTION", "DBus connection",
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
				netconfig_default_connection_info = { NULL, };

static gboolean __netconfig_is_connected(DBusMessageIter *array)
{
	gboolean is_connected = FALSE;

	while (dbus_message_iter_get_arg_type(array) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, variant;
		const char *key = NULL;
		const char *value = NULL;

		dbus_message_iter_recurse(array, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		if (g_str_equal(key, "State") != TRUE) {
			dbus_message_iter_next(array);
			continue;
		}

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &variant);

		if (dbus_message_iter_get_arg_type(&variant) ==
				DBUS_TYPE_STRING) {
			dbus_message_iter_get_basic(&variant, &value);

			if (g_str_equal(value, "ready") == TRUE ||
					g_str_equal(value, "online") == TRUE)
				is_connected = TRUE;
		}

		break;
	}

	return is_connected;
}

static char *__netconfig_get_default_profile(void)
{
	DBusMessage *message = NULL;
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
		DBusMessageIter array;
		const char *object_path = NULL;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &object_path);

		if (object_path == NULL) {
			dbus_message_iter_next(&dict);
			continue;
		}

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &array);

		if (__netconfig_is_connected(&array) == TRUE) {
			default_profile = g_strdup(object_path);
			break;
		}

		dbus_message_iter_next(&dict);
	}

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

				if(netconfig_default_connection_info.essid != NULL) {
					g_free(netconfig_default_connection_info.essid);
					netconfig_default_connection_info.essid = NULL;
				}
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

					if(netconfig_default_connection_info.ifname != NULL) {
						g_free(netconfig_default_connection_info.ifname);
						netconfig_default_connection_info.ifname = NULL;
					}
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

					if(netconfig_default_connection_info.ipaddress != NULL) {
						g_free(netconfig_default_connection_info.ipaddress);
						netconfig_default_connection_info.ipaddress = NULL;
					}
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

					/* TODO: support IPv6
					netconfig_default_connection_info.ipaddress = g_strdup(value);
					 */
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
					if (value != NULL && (strlen(value) > 0)) {
						if(netconfig_default_connection_info.proxy != NULL) {
							g_free(netconfig_default_connection_info.proxy);
							netconfig_default_connection_info.proxy = NULL;
						}
						netconfig_default_connection_info.proxy = g_strdup(value);
					}

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

static void __netconfig_adjust_tcp_buffer_size(void)
{
	int fdr = 0, fdw = 0;
	int fdrmax = 0, fdwmax = 0;
	const char *rbuf_size = NULL;
	const char *wbuf_size = NULL;
	const char *rmax_size = NULL;
	const char *wmax_size = NULL;
	const char *profile = netconfig_get_default_profile();

	if (profile == NULL) {
		DBG("There is no default connection");

		rbuf_size = NET_TCP_BUFFERSIZE_DEFAULT_READ;
		wbuf_size = NET_TCP_BUFFERSIZE_DEFAULT_WRITE;
	} else if (netconfig_is_wifi_profile(profile) == TRUE) {
		DBG("Default connection: Wi-Fi");

		rbuf_size = NET_TCP_BUFFERSIZE_WIFI_READ;
		wbuf_size = NET_TCP_BUFFERSIZE_WIFI_WRITE;
		rmax_size = NET_TCP_BUFFERSIZE_WIFI_RMEM_MAX;
		wmax_size = NET_TCP_BUFFERSIZE_WIFI_WMEM_MAX;
	} else if (netconfig_is_cellular_profile(profile) == TRUE) {
		int telephony_svctype = 0, telephony_pstype = 0;

		vconf_get_int(VCONFKEY_TELEPHONY_SVCTYPE, &telephony_svctype);
		vconf_get_int(VCONFKEY_TELEPHONY_PSTYPE, &telephony_pstype);

		DBG("Default cellular %d, %d", telephony_svctype, telephony_pstype);

		switch (telephony_pstype) {
		case VCONFKEY_TELEPHONY_PSTYPE_HSPA:
			rbuf_size = NET_TCP_BUFFERSIZE_HSPA_READ;
			wbuf_size = NET_TCP_BUFFERSIZE_HSPA_WRITE;
			break;
		case VCONFKEY_TELEPHONY_PSTYPE_HSUPA:
			rbuf_size = NET_TCP_BUFFERSIZE_HSUPA_READ;
			wbuf_size = NET_TCP_BUFFERSIZE_HSDPA_WRITE;
			break;
		case VCONFKEY_TELEPHONY_PSTYPE_HSDPA:
			rbuf_size = NET_TCP_BUFFERSIZE_HSDPA_READ;
			wbuf_size = NET_TCP_BUFFERSIZE_HSDPA_WRITE;
			break;
		default:
			switch (telephony_svctype) {
			case VCONFKEY_TELEPHONY_SVCTYPE_LTE:
				rbuf_size = NET_TCP_BUFFERSIZE_LTE_READ;
				wbuf_size = NET_TCP_BUFFERSIZE_LTE_WRITE;
				rmax_size = NET_TCP_BUFFERSIZE_LTE_RMEM_MAX;
				break;
			case VCONFKEY_TELEPHONY_SVCTYPE_3G:
				rbuf_size = NET_TCP_BUFFERSIZE_UMTS_READ;
				wbuf_size = NET_TCP_BUFFERSIZE_UMTS_WRITE;
				break;
			case VCONFKEY_TELEPHONY_SVCTYPE_2_5G_EDGE:
				rbuf_size = NET_TCP_BUFFERSIZE_EDGE_READ;
				wbuf_size = NET_TCP_BUFFERSIZE_EDGE_WRITE;
				break;
			case VCONFKEY_TELEPHONY_SVCTYPE_2_5G:
				rbuf_size = NET_TCP_BUFFERSIZE_GPRS_READ;
				wbuf_size = NET_TCP_BUFFERSIZE_GPRS_WRITE;
				break;
			default:
				/* TODO: Check LTE support */
				rbuf_size = NET_TCP_BUFFERSIZE_DEFAULT_READ;
				wbuf_size = NET_TCP_BUFFERSIZE_DEFAULT_WRITE;
				break;
			}
			break;
		}
	} else {
		DBG("Default TCP buffer configured");

		rbuf_size = NET_TCP_BUFFERSIZE_DEFAULT_READ;
		wbuf_size = NET_TCP_BUFFERSIZE_DEFAULT_WRITE;
	}

	if (rbuf_size != NULL) {
		fdr = open(NET_PROC_SYS_NET_IPV4_TCP_RMEM, O_RDWR | O_CLOEXEC);

		if (fdr < 0 || write(fdr, rbuf_size, strlen(rbuf_size)) < 0)
			ERR("Failed to set TCP read buffer size");

		if (fdr >= 0)
			close(fdr);
	}

	if (wbuf_size != NULL) {
		fdw = open(NET_PROC_SYS_NET_IPv4_TCP_WMEM, O_RDWR | O_CLOEXEC);

		if (fdw < 0 || write(fdw, wbuf_size, strlen(wbuf_size)) < 0)
			ERR("Failed to set TCP write buffer size");

		if (fdw >= 0)
			close(fdw);
	}

	/* As default */
	if (rmax_size == NULL)
		rmax_size = NET_TCP_BUFFERSIZE_WIFI_RMEM_MAX;
	if (wmax_size == NULL)
		wmax_size = NET_TCP_BUFFERSIZE_WIFI_WMEM_MAX;

	if (rmax_size != NULL) {
		fdrmax = open(NET_PROC_SYS_NET_CORE_RMEM_MAX, O_RDWR | O_CLOEXEC);

		if (fdrmax < 0 || write(fdrmax, rmax_size, strlen(rmax_size)) < 0)
			ERR("Failed to set TCP rmem_max size");

		if (fdrmax >= 0)
			close(fdrmax);
	}

	if (wmax_size != NULL) {
		fdwmax = open(NET_PROC_SYS_NET_CORE_WMEM_MAX, O_RDWR | O_CLOEXEC);

		if (fdwmax < 0 || write(fdwmax, wmax_size, strlen(wmax_size)) < 0)
			ERR("Failed to set TCP wmem_max size");

		if (fdwmax >= 0)
			close(fdwmax);
	}
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
		netconfig_set_vconf_int(VCONFKEY_NETWORK_STATUS, VCONFKEY_NETWORK_OFF);

		netconfig_set_vconf_str(VCONFKEY_NETWORK_IP, "");
		netconfig_set_vconf_str(VCONFKEY_NETWORK_PROXY, "");

		netconfig_set_vconf_int(VCONFKEY_NETWORK_CONFIGURATION_CHANGE_IND, 0);

		DBG("Successfully clear IP and PROXY up");
	} else if (profile != NULL) {
		char *old_ip = vconf_get_str(VCONFKEY_NETWORK_IP);
		char *old_proxy = vconf_get_str(VCONFKEY_NETWORK_PROXY);

		if (netconfig_is_wifi_profile(profile) == TRUE)
			netconfig_set_vconf_int(VCONFKEY_NETWORK_STATUS, VCONFKEY_NETWORK_WIFI);
		else if (netconfig_is_cellular_profile(profile) == TRUE)
			netconfig_set_vconf_int(VCONFKEY_NETWORK_STATUS, VCONFKEY_NETWORK_CELLULAR);
		else if (netconfig_is_ethernet_profile(profile) == TRUE)
			netconfig_set_vconf_int(VCONFKEY_NETWORK_STATUS, VCONFKEY_NETWORK_ETHERNET);
		else if (netconfig_is_bluetooth_profile(profile) == TRUE)
			netconfig_set_vconf_int(VCONFKEY_NETWORK_STATUS, VCONFKEY_NETWORK_BLUETOOTH);
		else
			netconfig_set_vconf_int(VCONFKEY_NETWORK_STATUS, VCONFKEY_NETWORK_OFF);

		if (g_strcmp0(old_ip, ip_addr) != 0) {
			if (ip_addr == NULL)
				netconfig_set_vconf_str(VCONFKEY_NETWORK_IP, "");
			else
				netconfig_set_vconf_str(VCONFKEY_NETWORK_IP, ip_addr);
		}
		g_free(old_ip);

		if (g_strcmp0(old_proxy, proxy_addr) != 0) {
			if (proxy_addr == NULL)
				netconfig_set_vconf_str(VCONFKEY_NETWORK_PROXY, "");
			else
				netconfig_set_vconf_str(VCONFKEY_NETWORK_PROXY, proxy_addr);
		}
		g_free(old_proxy);

		netconfig_set_vconf_int(VCONFKEY_NETWORK_CONFIGURATION_CHANGE_IND, 1);

		DBG("Successfully update default network configuration");
	}

	__netconfig_adjust_tcp_buffer_size();
}

static gboolean __netconfig_is_tech_state_connected(void)
{
	gboolean ret = FALSE;
	DBusMessage *message;
	DBusMessageIter iter, array;

	message = netconfig_invoke_dbus_method(CONNMAN_SERVICE,
			CONNMAN_MANAGER_PATH, CONNMAN_MANAGER_INTERFACE,
			"GetTechnologies", NULL);

	if (message == NULL) {
		DBG("Fail to get technology state");
		return FALSE;
	}

	if (!dbus_message_iter_init(message, &iter)) {
		DBG("Message does not have parameters");
		goto done;
	}

	dbus_message_iter_recurse(&iter, &array);

	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_STRUCT) {
		DBusMessageIter entry, dict;
		char *path = NULL;

		dbus_message_iter_recurse(&array, &entry);
		dbus_message_iter_get_basic(&entry, &path);

		if (path == NULL) {
			dbus_message_iter_next(&array);
			continue;
		}

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &dict);

		while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
			DBusMessageIter entry1, value1;
			const char *key;
			dbus_bool_t data;

			dbus_message_iter_recurse(&dict, &entry1);
			dbus_message_iter_get_basic(&entry1, &key);

			if (0 == g_strcmp0(key, "Connected")) {
				dbus_message_iter_next(&entry1);
				dbus_message_iter_recurse(&entry1, &value1);

				if (dbus_message_iter_get_arg_type(&value1) ==
						DBUS_TYPE_BOOLEAN) {
					dbus_message_iter_get_basic(&value1, &data);
					DBG("%s [%s: %s]", path, key, data ? "True" : "False");

					if (TRUE == data) {
						ret = TRUE;
						goto done;
					}
				}
			}
			dbus_message_iter_next(&dict);
		}

		dbus_message_iter_next(&array);
	}

done:
	if (message != NULL)
		dbus_message_unref(message);

	return ret;
}

static void __netconfig_update_if_service_connected(void)
{
	DBusMessage *message;
	DBusMessageIter iter, array;

	message = netconfig_invoke_dbus_method(CONNMAN_SERVICE,
			CONNMAN_MANAGER_PATH, CONNMAN_MANAGER_INTERFACE,
			"GetServices", NULL);

	if (message == NULL) {
		DBG("Fail to get services");
		return;
	}

	if (!dbus_message_iter_init(message, &iter)) {
		DBG("Message does not have parameters");
		goto done;
	}

	dbus_message_iter_recurse(&iter, &array);

	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_STRUCT) {
		DBusMessageIter entry, dict;
		char *path = NULL;

		dbus_message_iter_recurse(&array, &entry);
		dbus_message_iter_get_basic(&entry, &path);

		if (path == NULL) {
			dbus_message_iter_next(&array);
			continue;
		}

		if (g_str_has_prefix(path,
						CONNMAN_WIFI_SERVICE_PROFILE_PREFIX) == TRUE) {
			if (g_strrstr(path + strlen(CONNMAN_WIFI_SERVICE_PROFILE_PREFIX),
							"hidden") != NULL) {
				/* skip hidden profiles */
				dbus_message_iter_next(&array);
				continue;
			}
			/* Process this */
		} else if (g_str_has_prefix(path,
						CONNMAN_CELLULAR_SERVICE_PROFILE_PREFIX) == TRUE) {
			/* Process this */
		} else {
			dbus_message_iter_next(&array);
			continue;
		}

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &dict);

		while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
			DBusMessageIter entry1, value1;
			const char *key, *sdata;

			dbus_message_iter_recurse(&dict, &entry1);
			dbus_message_iter_get_basic(&entry1, &key);

			if (0 == g_strcmp0(key, "State")) {
				dbus_message_iter_next(&entry1);
				dbus_message_iter_recurse(&entry1, &value1);

				if (dbus_message_iter_get_arg_type(&value1) ==
						DBUS_TYPE_STRING) {
					dbus_message_iter_get_basic(&value1, &sdata);
					DBG("%s [%s: %s]", path, key, sdata);

					if (0 == g_strcmp0(sdata, "online") ||
							0 == g_strcmp0(sdata, "ready")) {

						/* Found a connected WiFi / 3G service.
						 * Lets update the default profile info.
						 */
						netconfig_update_default_profile(path);
						goto done;
					}
				}
			}
			dbus_message_iter_next(&dict);
		}

		dbus_message_iter_next(&array);
	}

done:
	if (message != NULL)
		dbus_message_unref(message);
}

const char *netconfig_get_default_profile(void)
{
	return netconfig_default_connection_info.profile;
}

const char *netconfig_get_default_ifname(void)
{
	return netconfig_default_connection_info.ifname;
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

static int __netconfig_reset_ipv4_socket(void)
{
	int ret;
	int fd;
	struct ifreq ifr;
	struct sockaddr_in sai;
	const char *ipaddr = netconfig_get_default_ipaddress();
	DBG("ipaddr-[%s]", ipaddr);

	if (!ipaddr)
		return -1;

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0)
		return -1;

	memset(&sai, 0, sizeof(struct sockaddr_in));
	sai.sin_family = AF_INET;
	sai.sin_port = 0;
	if (!inet_aton(ipaddr, &sai.sin_addr)) {
		DBG("fail to inet_aton()");
		close(fd);
		return -1;
	}

	memset(&ifr, 0, sizeof(struct ifreq));
	memcpy(&ifr.ifr_addr, &sai, sizeof(sai));
	g_strlcpy((char *)ifr.ifr_name, WIFI_IFNAME, IFNAMSIZ);

#ifndef SIOCKILLADDR
#define SIOCKILLADDR    0x8939
#endif

	ret = ioctl(fd, SIOCKILLADDR, &ifr);
	if (ret < 0) {
		DBG("fail to ioctl[SIOCKILLADDR]");
		close(fd);
		return -1;
	}

	close(fd);
	return 0;
}

void netconfig_update_default_profile(const char *profile)
{
	char *default_profile = NULL;
	static char *old_profile = NULL;

	/* It's automatically updated by signal-handler
	 * DO NOT update manually
	 *
	 * It is going to update default connection information
	 */
	if (netconfig_default_connection_info.profile != NULL) {
		if (netconfig_is_wifi_profile(
				netconfig_default_connection_info.profile) == TRUE)
			__netconfig_reset_ipv4_socket();

		g_free(old_profile);
		old_profile = strdup(netconfig_default_connection_info.profile);

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
		netconfig_default_connection_info.profile = default_profile;
	} else
		netconfig_default_connection_info.profile = g_strdup(profile);

	__netconfig_get_default_connection_info(
			netconfig_default_connection_info.profile);

	__netconfig_update_default_connection_info();
}

void netconfig_update_default(void)
{
	if (__netconfig_is_tech_state_connected() == TRUE)
		__netconfig_update_if_service_connected();
	else
		__netconfig_adjust_tcp_buffer_size();
}

char *netconfig_network_get_ifname(const char *profile)
{
	DBusMessage *message = NULL;
	DBusMessageIter iter, array;
	char *ifname = NULL;

	if (profile == NULL)
		return NULL;

	message = netconfig_invoke_dbus_method(CONNMAN_SERVICE, profile,
			CONNMAN_SERVICE_INTERFACE, "GetProperties", NULL);
	if (message == NULL) {
		ERR("Failed to get service properties");
		return NULL;
	}

	if (dbus_message_get_type(message) == DBUS_MESSAGE_TYPE_ERROR) {
		const char *ptr = dbus_message_get_error_name(message);
		ERR("Error!!! Error message received [%s]", ptr);
		goto done;
	}

	dbus_message_iter_init(message, &iter);
	dbus_message_iter_recurse(&iter, &array);

	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, variant, iter1, iter2, iter3;
		const char *key = NULL;

		dbus_message_iter_recurse(&array, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		if (g_str_equal(key, "Ethernet") == TRUE) {
			dbus_message_iter_next(&entry);
			dbus_message_iter_recurse(&entry, &variant);
			dbus_message_iter_recurse(&variant, &iter1);

			while (dbus_message_iter_get_arg_type(&iter1)
					== DBUS_TYPE_DICT_ENTRY) {
				const char *value;

				dbus_message_iter_recurse(&iter1, &iter2);
				dbus_message_iter_get_basic(&iter2, &key);

				if (g_str_equal(key, "Interface") == TRUE) {
					dbus_message_iter_next(&iter2);
					dbus_message_iter_recurse(&iter2, &iter3);
					dbus_message_iter_get_basic(&iter3, &value);

					ifname = g_strdup(value);
				}
				dbus_message_iter_next(&iter1);
			}
		}
		dbus_message_iter_next(&array);
	}

done:
	if (message != NULL)
		dbus_message_unref(message);

	return ifname;
}

gboolean netconfig_iface_network_state_add_route(
		NetconfigNetworkState *master,
		gchar *ip_addr, gchar *netmask,
		gchar *interface, gboolean *result, GError **error)
{
	int rv = 0;
	const char *path = ROUTE_EXEC_PATH;
	char *const args[] = { "/sbin/route", "add", "-net", ip_addr,
			"netmask", netmask, "dev", interface, NULL };
	char *const envs[] = { NULL };

	DBG("ip_addr(%s), netmask(%s), interface(%s)", ip_addr, netmask, interface);

	if (ip_addr == NULL || netmask == NULL || interface == NULL) {
		ERR("Invalid parameter");

		netconfig_error_invalid_parameter(error);
		*result = FALSE;
		return FALSE;
	}

	rv = netconfig_execute_file(path, args, envs);
	if (rv < 0) {
		ERR("Failed to add a new route");

		netconfig_error_permission_denied(error);
		*result = FALSE;
		return FALSE;
	}

	DBG("Successfully added a new route");
	*result = TRUE;
	return TRUE;
}

gboolean netconfig_iface_network_state_remove_route(
		NetconfigNetworkState *master,
		gchar *ip_addr, gchar *netmask,
		gchar *interface, gboolean *result, GError **error)
{
	int rv = 0;
	const char *path = ROUTE_EXEC_PATH;
	char *const args[] = { "/sbin/route", "del", "-net", ip_addr,
			"netmask", netmask, "dev", interface, NULL };
	char *const envs[] = { NULL };

	DBG("ip_addr(%s), netmask(%s), interface(%s)", ip_addr, netmask, interface);

	if (ip_addr == NULL || netmask == NULL || interface == NULL) {
		ERR("Invalid parameter");

		netconfig_error_invalid_parameter(error);
		*result = FALSE;
		return FALSE;
	}

	rv = netconfig_execute_file(path, args, envs);
	if (rv < 0) {
		ERR("Failed to remove a new route");

		netconfig_error_permission_denied(error);
		*result = FALSE;
		return FALSE;
	}

	DBG("Successfully remove a new route");
	*result = TRUE;
	return TRUE;
}

gpointer netconfig_network_state_create_and_init(DBusGConnection *connection)
{
	GObject *object;

	g_return_val_if_fail(connection != NULL, NULL);

	object = g_object_new(NETCONFIG_TYPE_NETWORK_STATE, "connection",
			connection, "path", NETCONFIG_NETWORK_STATE_PATH, NULL);

	dbus_g_connection_register_g_object(connection,
									NETCONFIG_NETWORK_STATE_PATH, object);

	return object;
}

gboolean netconfig_iface_network_state_check_get_privilege()
{
		return TRUE;
}

gboolean netconfig_iface_network_state_check_profile_privilege()
{
		return TRUE;
}
