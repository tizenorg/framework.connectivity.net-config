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
#include <stdlib.h>
#include <aul.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <ITapiSim.h>
#include <TapiUtility.h>

#include "log.h"
#include "util.h"
#include "netdbus.h"
#include "neterror.h"
#include "emulator.h"
#include "wifi-state.h"
#include "wifi-power.h"
#include "network-state.h"
#include "network-monitor.h"
#include "netsupplicant.h"
#include "wifi-tel-intf.h"
#include "clatd-handler.h"

#include "generated-code.h"
/* Define TCP buffer sizes for various networks */
/* ReadMin, ReadInitial, ReadMax */ /* WriteMin, WriteInitial, WriteMax */
#define NET_TCP_BUFFERSIZE_DEFAULT_READ		"4096 87380 704512"
#define NET_TCP_BUFFERSIZE_DEFAULT_WRITE	"4096 16384 110208"
#define NET_TCP_BUFFERSIZE_WIFI_READ		"524288 1048576 2560000"
#define NET_TCP_BUFFERSIZE_WIFI_WRITE		"524288 1048576 2560000"
#define NET_TCP_BUFFERSIZE_LTE_READ		"524288 1048576 2560000"
#define NET_TCP_BUFFERSIZE_LTE_WRITE		"524288 1048576 2560000"
#define NET_TCP_BUFFERSIZE_UMTS_READ		"4094 87380 704512"
#define NET_TCP_BUFFERSIZE_UMTS_WRITE		"4096 16384 110208"
#define NET_TCP_BUFFERSIZE_HSPA_READ		"4092 87380 704512"
#define NET_TCP_BUFFERSIZE_HSPA_WRITE		"4096 16384 262144"
#define NET_TCP_BUFFERSIZE_HSDPA_READ		"4092 87380 704512"
#define NET_TCP_BUFFERSIZE_HSDPA_WRITE		"4096 16384 262144"
#define NET_TCP_BUFFERSIZE_HSUPA_READ		"4092 87380 704512"
#define NET_TCP_BUFFERSIZE_HSUPA_WRITE		"4096 16384 262144"
#define NET_TCP_BUFFERSIZE_HSPAP_READ		"4092 87380 1220608"
#define NET_TCP_BUFFERSIZE_HSPAP_WRITE		"4096 16384 1220608"
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

static Network *netconfigstate = NULL;

struct netconfig_default_connection {
	char *profile;
	char *ifname;
	char *ipaddress;
	char *ipaddress6;
	char *proxy;
	char *essid;
	unsigned int freq;
};

static struct netconfig_default_connection
				netconfig_default_connection_info = { NULL, };

gboolean netconfig_iface_network_state_ethernet_cable_state(gint32 *state);

static gboolean __netconfig_is_connected(GVariantIter *array)
{
	gboolean is_connected = FALSE;
	GVariant *variant = NULL;
	gchar *key = NULL;
	const gchar *value = NULL;

	while (g_variant_iter_loop(array, "{sv}", &key, &variant)) {
		if (g_strcmp0(key, "State") != 0) {
			continue;
		}

		if (g_variant_is_of_type(variant, G_VARIANT_TYPE_STRING)) {
			value = g_variant_get_string(variant, NULL);
			if (g_strcmp0(value, "ready") == 0 || g_strcmp0(value, "online") == 0)
				is_connected = TRUE;
		}

		g_free(key);
		g_variant_unref(variant);
		break;
	}

	return is_connected;
}

static char *__netconfig_get_default_profile(void)
{
	GVariant *message = NULL;
	GVariantIter *iter;
	GVariantIter *next;
	gchar *default_profile = NULL;
	gchar *object_path;

	message = netconfig_invoke_dbus_method(CONNMAN_SERVICE,
			CONNMAN_MANAGER_PATH, CONNMAN_MANAGER_INTERFACE,
			"GetServices", NULL);
	if (message == NULL) {
		ERR("Failed to get profiles");
		return NULL;
	}

	g_variant_get(message, "(a(oa{sv}))", &iter);
	while (g_variant_iter_loop(iter, "(oa{sv})", &object_path, &next)) {
		if (object_path == NULL) {
			continue;
		}

		if(netconfig_is_cellular_profile(object_path) && !netconfig_is_cellular_internet_profile(object_path)){
			continue;
		}

		if (__netconfig_is_connected(next) == TRUE) {
			default_profile = g_strdup(object_path);
			g_free(object_path);
			g_variant_iter_free(next);
			break;
		}
	}
	g_variant_iter_free(iter);
	g_variant_unref(message);

	return default_profile;
}

static void __netconfig_get_default_connection_info(const char *profile)
{
	GVariant *message = NULL, *variant = NULL, *variant2 = NULL;
	GVariantIter *iter = NULL, *iter1 = NULL;
	GVariant *next = NULL;
	gchar *key = NULL;
	gchar *key1 = NULL;
	gchar *key2 = NULL;

	message = netconfig_invoke_dbus_method(CONNMAN_SERVICE, profile,
			CONNMAN_SERVICE_INTERFACE, "GetProperties", NULL);
	if (message == NULL) {
		ERR("Failed to get service properties");
		goto done;
	}

	g_variant_get(message, "(a{sv})", &iter);
	while (g_variant_iter_loop(iter, "{sv}", &key, &next)) {
		const gchar *value = NULL;
		guint16 freq = 0;
		if (g_strcmp0(key, "Name") == 0 &&
				netconfig_is_wifi_profile(profile) == TRUE) {
			if (g_variant_is_of_type(next, G_VARIANT_TYPE_STRING)) {
				value = g_variant_get_string(next, NULL);

				netconfig_default_connection_info.essid = g_strdup(value);
			}
		} else if (g_strcmp0(key, "Ethernet") == 0) {
			g_variant_get(next, "a{sv}", &iter1);
			while (g_variant_iter_loop(iter1, "{sv}", &key1, &variant)) {
				if (g_strcmp0(key1, "Interface") == 0) {
					value = g_variant_get_string(variant, NULL);
					netconfig_default_connection_info.ifname = g_strdup(value);
				}
			}
		} else if (g_strcmp0(key, "IPv4") == 0) {
			g_variant_get(next, "a{sv}", &iter1);
			while (g_variant_iter_loop(iter1, "{sv}", &key1, &variant)) {
				if (g_strcmp0(key1, "Address") == 0) {
					value = g_variant_get_string(variant, NULL);
					netconfig_default_connection_info.ipaddress = g_strdup(value);
				}
			}
		} else if (g_strcmp0(key, "IPv6") == 0) {
			g_variant_get(next, "a{sv}", &iter1);
			while (g_variant_iter_loop(iter1, "{sv}", &key1, &variant)) {
				if (g_strcmp0(key1, "Address") == 0) {
					value = g_variant_get_string(variant, NULL);
					netconfig_default_connection_info.ipaddress6 = g_strdup(value);
				}
			}
		} else if (g_strcmp0(key, "Proxy") == 0) {
			g_variant_get(next, "a{sv}", &iter1);
			while (g_variant_iter_loop(iter1, "{sv}", &key2, &variant2)) {
				GVariantIter *iter_sub = NULL;

				if (g_strcmp0(key2, "Servers") == 0) {
					if (!g_variant_is_of_type(variant2, G_VARIANT_TYPE_STRING_ARRAY)) {
						g_free(key2);
						g_variant_unref(variant2);
						break;
					}

					g_variant_get(variant2, "as", &iter_sub);
					g_variant_iter_loop(iter_sub, "s", &value);
					g_variant_iter_free(iter_sub);
					if (value != NULL && (strlen(value) > 0))
						netconfig_default_connection_info.proxy = g_strdup(value);
				} else if (g_strcmp0(key2, "Method") == 0) {
					if (g_variant_is_of_type(variant2, G_VARIANT_TYPE_STRING)) {
						g_free(key2);
						g_variant_unref(variant2);
						break;
					}

					value = g_variant_get_string(variant2, NULL);
					if (g_strcmp0(value, "direct") == 0) {
						g_free(netconfig_default_connection_info.proxy);
						netconfig_default_connection_info.proxy = NULL;

						g_free(key2);
						g_variant_unref(variant2);
						break;
					}
				}
			}
		} else if (g_strcmp0(key, "Frequency") == 0) {
			if (g_variant_is_of_type(next, G_VARIANT_TYPE_UINT16)) {
				freq = g_variant_get_uint16(next);
				netconfig_default_connection_info.freq = freq;
			}
		}
	}

done:
	if (message)
		g_variant_unref(message);

	if (iter)
		g_variant_iter_free (iter);

	if (iter1)
		g_variant_iter_free (iter1);

	return;
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
		TapiHandle *tapi_handle = NULL;
		int telephony_svctype = 0, telephony_pstype = 0;

		tapi_handle = (TapiHandle *)netconfig_tel_init();
		if (NULL != tapi_handle) {
			tel_get_property_int(tapi_handle,
					TAPI_PROP_NETWORK_SERVICE_TYPE,
					&telephony_svctype);
			tel_get_property_int(tapi_handle, TAPI_PROP_NETWORK_PS_TYPE,
					&telephony_pstype);
			netconfig_tel_deinit();
		}

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
#if !defined TIZEN_WEARABLE
		case VCONFKEY_TELEPHONY_PSTYPE_HSPAP:
			rbuf_size = NET_TCP_BUFFERSIZE_HSPAP_READ;
			wbuf_size = NET_TCP_BUFFERSIZE_HSPAP_WRITE;
			break;
#endif
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
	const char *ip_addr6 = netconfig_get_default_ipaddress6();
	const char *proxy_addr = netconfig_get_default_proxy();
	unsigned int freq = netconfig_get_default_frequency();

	if (emulator_is_emulated() == TRUE)
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
		netconfig_set_vconf_int("memory/private/wifi/frequency", 0);

		DBG("Successfully clear IP and PROXY up");

		/* Disable clatd if it is in running state */
		netconfig_clatd_disable();
	}
	else if (profile != NULL) {
		char *old_ip = vconf_get_str(VCONFKEY_NETWORK_IP);
		char *old_proxy = vconf_get_str(VCONFKEY_NETWORK_PROXY);

		if (netconfig_is_wifi_profile(profile) == TRUE) {
			netconfig_set_vconf_int(VCONFKEY_NETWORK_STATUS, VCONFKEY_NETWORK_WIFI);
			netconfig_set_vconf_int("memory/private/wifi/frequency", freq);
		}
		else if (netconfig_is_cellular_profile(profile) ){

			if( !netconfig_is_cellular_internet_profile(profile)){
				DBG("connection is not a internet profile - stop to update the cellular state");
				return;
			}

			netconfig_set_vconf_int(VCONFKEY_NETWORK_STATUS, VCONFKEY_NETWORK_CELLULAR);

			/* Enable clatd if IPv6 is set and no IPv4 address */
			if (!ip_addr && ip_addr6 )
				netconfig_clatd_enable();
		}
		else if (netconfig_is_ethernet_profile(profile) == TRUE){
			netconfig_set_vconf_int(VCONFKEY_NETWORK_STATUS, VCONFKEY_NETWORK_ETHERNET);
		}
		else if (netconfig_is_bluetooth_profile(profile) == TRUE){
			netconfig_set_vconf_int(VCONFKEY_NETWORK_STATUS, VCONFKEY_NETWORK_BLUETOOTH);
		}
		else{
			netconfig_set_vconf_int(VCONFKEY_NETWORK_STATUS, VCONFKEY_NETWORK_OFF);
		}

		if (g_strcmp0(old_ip, ip_addr) != 0 || old_ip == NULL) {
			if (ip_addr != NULL)
				netconfig_set_vconf_str(VCONFKEY_NETWORK_IP, ip_addr);
			else if (ip_addr6 != NULL)
				netconfig_set_vconf_str(VCONFKEY_NETWORK_IP, ip_addr6);
			else
				netconfig_set_vconf_str(VCONFKEY_NETWORK_IP, "");
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

		/* Disable clatd if it is in running state */
		if (netconfig_is_cellular_profile(profile) != TRUE)
			netconfig_clatd_disable();
	}

	__netconfig_adjust_tcp_buffer_size();
}

static gboolean __netconfig_is_tech_state_connected(void)
{
	gboolean ret = FALSE;
	GVariant *message = NULL, *variant;
	GVariantIter *iter, *next;
	gchar *path;
	gchar *key;

	message = netconfig_invoke_dbus_method(CONNMAN_SERVICE,
			CONNMAN_MANAGER_PATH, CONNMAN_MANAGER_INTERFACE,
			"GetTechnologies", NULL);

	if (message == NULL) {
		DBG("Fail to get technology state");
		return FALSE;
	}

	g_variant_get(message, "(a(oa{sv}))", &iter);
	while (g_variant_iter_loop(iter, "(oa{sv})", &path, &next)) {
		if (path == NULL) {
			continue;
		}

		while (g_variant_iter_loop(next, "{sv}", &key, &variant)) {
			gboolean data;
			if (g_strcmp0(key, "Connected") == 0) {
				data = g_variant_get_boolean(variant);
				DBG("%s [%s: %s]", path, key, data ? "True" : "False");
				if (TRUE == data) {
					ret = TRUE;
					g_free(path);
					g_free(key);
					g_variant_unref(variant);
					g_variant_iter_free(next);
					goto done;
				}
			}
		}
	}

done:
	g_variant_iter_free(iter);
	g_variant_unref(message);

	return ret;
}

static void __netconfig_update_if_service_connected(void)
{
	GVariant *message = NULL, *var;
	GVariantIter *iter, *next;
	gchar *path;
	gchar *key;

	message = netconfig_invoke_dbus_method(CONNMAN_SERVICE,
			CONNMAN_MANAGER_PATH, CONNMAN_MANAGER_INTERFACE,
			"GetServices", NULL);

	if (message == NULL) {
		ERR("Failed to get services");
		return;
	}

	g_variant_get(message, "(a(oa{sv}))", &iter);
	while (g_variant_iter_loop(iter, "(oa{sv})", &path, &next)) {
		if (path == NULL) {
			continue;
		}

		if (g_str_has_prefix(path,
						CONNMAN_WIFI_SERVICE_PROFILE_PREFIX) == TRUE) {
			if (g_strrstr(path + strlen(CONNMAN_WIFI_SERVICE_PROFILE_PREFIX),
							"hidden") != NULL) {
				/* skip hidden profiles */
				continue;
			}
			/* Process this */
		} else if (g_str_has_prefix(path,
						CONNMAN_CELLULAR_SERVICE_PROFILE_PREFIX) == TRUE) {
			/* Process this */
		} else {
			continue;
		}

		while (g_variant_iter_loop(next, "{sv}", &key, &var)) {
			if (g_strcmp0(key, "State") == 0) {
				const gchar *sdata = NULL;
				sdata = g_variant_get_string(var, NULL);
				DBG("%s [%s: %s]", path, key, sdata);

				if (g_strcmp0(sdata, "online") == 0 || g_strcmp0(sdata, "ready") == 0) {

					/* Found a connected WiFi / 3G service.
					 * Lets update the default profile info.
					 */
					netconfig_update_default_profile((const gchar*)path);
					g_free(key);
					g_free(path);
					g_variant_unref(var);
					g_variant_iter_free(next);
					goto done;
				}
			}
		}
	}
done:
	g_variant_iter_free(iter);
	g_variant_unref(message);

	return;
}

static void __netconfig_network_notify_result(const char *sig_name, const char *key)
{
	gboolean reply;
	GVariantBuilder *builder = NULL;
	GDBusConnection *connection = NULL;
	GError *error = NULL;
	const char *prop_key = "key";

	INFO("[Signal] %s %s", sig_name, key);

	connection = netdbus_get_connection();
	if (connection == NULL) {
		ERR("Failed to get GDBus Connection");
		return;
	}

	builder = g_variant_builder_new(G_VARIANT_TYPE ("a{sv}"));
	g_variant_builder_add(builder, "{sv}", prop_key, g_variant_new("(s)", key));

	reply = g_dbus_connection_emit_signal(connection,
			NULL,
			NETCONFIG_NETWORK_PATH,
			NETCONFIG_NETWORK_INTERFACE,
			sig_name,
			g_variant_builder_end(builder),
			&error);

	if (builder)
		g_variant_builder_unref(builder);

	if (reply != TRUE) {
		if (error != NULL) {
			ERR("Failed to send signal [%s]", error->message);
			g_error_free(error);
		}
		return;
	}

	INFO("Sent signal (%s), key (%s)", sig_name, key);
	return;
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

const char *netconfig_get_default_ipaddress6(void)
{
	return netconfig_default_connection_info.ipaddress6;
}

const char *netconfig_get_default_proxy(void)
{
	return netconfig_default_connection_info.proxy;
}

unsigned int netconfig_get_default_frequency(void)
{
	return netconfig_default_connection_info.freq;
}

const char *netconfig_wifi_get_connected_essid(const char *default_profile)
{
	if (default_profile == NULL)
		return NULL;

	if (netconfig_is_wifi_profile(default_profile) != TRUE)
		return NULL;

	if (g_strcmp0(default_profile, netconfig_default_connection_info.profile) != 0)
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
	static char *old_profile = NULL;

	/* It's automatically updated by signal-handler
	 * DO NOT update manually
	 *
	 * It is going to update default connection information
	 */

	if (netconfig_default_connection_info.profile != NULL) {

		if (netconfig_is_wifi_profile(netconfig_default_connection_info.profile))
			__netconfig_reset_ipv4_socket();

		g_free(old_profile);
		old_profile = strdup(netconfig_default_connection_info.profile);

		g_free(netconfig_default_connection_info.profile);
		netconfig_default_connection_info.profile = NULL;

		g_free(netconfig_default_connection_info.ifname);
		netconfig_default_connection_info.ifname = NULL;

		g_free(netconfig_default_connection_info.ipaddress);
		netconfig_default_connection_info.ipaddress = NULL;

		g_free(netconfig_default_connection_info.ipaddress6);
		netconfig_default_connection_info.ipaddress6 = NULL;

		g_free(netconfig_default_connection_info.proxy);
		netconfig_default_connection_info.proxy = NULL;

		netconfig_default_connection_info.freq = 0;

		if (wifi_state_get_service_state() != NETCONFIG_WIFI_CONNECTED) {
			g_free(netconfig_default_connection_info.essid);
			netconfig_default_connection_info.essid = NULL;
		}
	}

	//default profile is NULL and new connected profile is NULL
	if( !profile ){
		profile = __netconfig_get_default_profile();

		if (profile && netconfig_is_cellular_profile(profile) &&
			!netconfig_is_cellular_internet_profile(profile)){
			DBG("not a default cellular profile");
			profile = NULL;
		}

		if(!profile){
			__netconfig_update_default_connection_info();
			return;
		}
	}

	netconfig_default_connection_info.profile = g_strdup(profile);
	__netconfig_get_default_connection_info(profile);
	__netconfig_update_default_connection_info();

}

void netconfig_update_default(void)
{
	if (__netconfig_is_tech_state_connected() == TRUE)
		__netconfig_update_if_service_connected();
	else
		__netconfig_adjust_tcp_buffer_size();
}

char *netconfig_get_ifname(const char *profile)
{
	GVariant *message = NULL, *variant;
	GVariantIter *iter, *next;
	gchar *key;
	gchar *key1;
	const gchar *value = NULL;
	gchar *ifname = NULL;

	if (profile == NULL)
		return NULL;

	message = netconfig_invoke_dbus_method(CONNMAN_SERVICE, profile,
			CONNMAN_SERVICE_INTERFACE, "GetProperties", NULL);
	if (message == NULL) {
		ERR("Failed to get service properties");
		return NULL;
	}

	g_variant_get(message, "(a{sv})", &iter);
	while (g_variant_iter_loop(iter, "{sv}", &key, &next)) {
		if (g_strcmp0(key, "Ethernet") == 0) {
			while (g_variant_iter_loop(next, "{sv}", &key1, &variant)) {
				if (g_strcmp0(key1, "Interface") == 0) {
					value = g_variant_get_string(variant, NULL);
					ifname = g_strdup(value);
				}
			}
		}
	}

	g_variant_unref(message);

	g_variant_iter_free(iter);

	return ifname;
}

/* Check Ethernet Cable Plug-in /Plug-out Status */
void netconfig_network_notify_ethernet_cable_state(const char *key)
{
       __netconfig_network_notify_result("EthernetCableState", key);
}

static gboolean handle_add_route(
		Network *object,
		GDBusMethodInvocation *context,
		gchar *ip_addr,
		gchar *netmask,
		gchar *interface,  gchar *gateway, gint address_family)
{
	const gchar *path = ROUTE_EXEC_PATH;
	gchar *const args[] = { "/sbin/route", "add", "-net", ip_addr,
		"netmask", netmask, "dev", interface, NULL };
	gchar *const envs[] = { NULL };
	const gchar* buf = NULL;
	gchar* ch = NULL;
	int prefix_len = 0;
	int pos = 0;

	DBG("ip_addr(%s), netmask(%s), interface(%s), gateway(%s)", ip_addr, netmask, interface, gateway);

	switch(address_family) {
		case AF_INET:
			if (ip_addr == NULL || netmask == NULL || interface == NULL) {
				ERR("Invalid parameter");
				netconfig_error_invalid_parameter(context);
				return FALSE;
			}

			if (netconfig_execute_file(path, args, envs) < 0) {
				DBG("Failed to add a new route");
				netconfig_error_permission_denied(context);
				return FALSE;
			}

			break;
		case AF_INET6:
			if (ip_addr == NULL || interface == NULL || gateway == NULL) {
				ERR("Invalid parameter");
				netconfig_error_invalid_parameter(context);
				return FALSE;
			}

			buf = ip_addr;
			ch = strchr(buf, '/');
			pos = ch - buf + 1;
			if (ch) {
				prefix_len = atoi(ch + 1);
				ip_addr[pos-1] = '\0';
			} else {
				prefix_len = 128;
			}

			if (netconfig_add_route_ipv6(ip_addr, interface, gateway, prefix_len) < 0) {
				DBG("Failed to add a new route");
				netconfig_error_permission_denied(context);
				return FALSE;
			}
			break;
		default:
			DBG("Unknown Address Family");
			netconfig_error_invalid_parameter(context);
			return FALSE;
	}

	DBG("Successfully added a new route");
	network_complete_add_route(object, context, TRUE);
	return TRUE;
}

static gboolean handle_remove_route(
		Network *object,
		GDBusMethodInvocation *context,
		gchar *ip_addr,
		gchar *netmask,
		gchar *interface, gchar *gateway, gint address_family)
{
	const char *path = ROUTE_EXEC_PATH;
	gchar *const args[] = { "/sbin/route", "del", "-net", ip_addr,
		"netmask", netmask, "dev", interface, NULL };
	char *const envs[] = { NULL };
	const char* buf = NULL;
	char* ch = NULL;
	int prefix_len = 0;
	int pos = 0;

	DBG("ip_addr(%s), netmask(%s), interface(%s), gateway(%s)", ip_addr, netmask, interface, gateway);

	switch(address_family) {
		case AF_INET:
			if (ip_addr == NULL || netmask == NULL || interface == NULL) {
				DBG("Invalid parameter!");
				netconfig_error_invalid_parameter(context);
				return FALSE;
			}
			if (netconfig_execute_file(path, args, envs) < 0) {
				DBG("Failed to remove the route");
				netconfig_error_permission_denied(context);
				return FALSE;
			}
			break;
		case AF_INET6:
			if (ip_addr == NULL || interface == NULL || gateway == NULL) {
				DBG("Invalid parameter!");
				netconfig_error_invalid_parameter(context);
				return FALSE;
			}

			buf = ip_addr;
			ch = strchr(buf, '/');
			pos = ch - buf + 1;
			if (ch) {
				prefix_len = atoi(ch + 1);
				ip_addr[pos-1] = '\0';
			} else {
				prefix_len = 128;
			}

			if (netconfig_del_route_ipv6(ip_addr, interface, gateway, prefix_len) < 0) {
				DBG("Failed to remove the route");
				netconfig_error_permission_denied(context);
				return FALSE;
			}
			break;
		default:
			DBG("Unknown Address Family");
			netconfig_error_invalid_parameter(context);
			return FALSE;
	}

	DBG("Successfully removed the route");
	network_complete_remove_route(object, context, TRUE);
	return TRUE;
}

static gboolean handle_check_get_privilege(Network *object,
		GDBusMethodInvocation *context)
{
	network_complete_check_get_privilege(object, context);
	return TRUE;
}


static gboolean handle_check_profile_privilege(Network *object,
		GDBusMethodInvocation *context)
{
	network_complete_check_profile_privilege(object, context);
	return TRUE;
}

gboolean netconfig_iface_network_state_ethernet_cable_state(gint32 *state)
{
       int ret = 0;

       ret = netconfig_get_ethernet_cable_state(state);
       if(ret != 0) {
               DBG("Failed to get ethernet cable state");
               return FALSE;
       }

       DBG("Successfully get ethernet cable state[%d]", state);
       return TRUE;
}

void state_object_create_and_init(void)
{
	DBG("Creating network state object");
	GDBusInterfaceSkeleton *interface_network = NULL;
	GDBusConnection *connection = NULL;
	GDBusObjectManagerServer *server = netdbus_get_state_manager();
	if (server == NULL)
		return;

	connection = netdbus_get_connection();
	g_dbus_object_manager_server_set_connection(server, connection);

	/*Interface netconfig.network*/
	netconfigstate = network_skeleton_new();

	interface_network = G_DBUS_INTERFACE_SKELETON(netconfigstate);
	g_signal_connect(netconfigstate, "handle-add-route",
				G_CALLBACK(handle_add_route), NULL);
	g_signal_connect(netconfigstate, "handle-check-get-privilege",
				G_CALLBACK(handle_check_get_privilege), NULL);
	g_signal_connect(netconfigstate, "handle-check-profile-privilege",
				G_CALLBACK(handle_check_profile_privilege), NULL);
	g_signal_connect(netconfigstate, "handle-remove-route",
				G_CALLBACK(handle_remove_route), NULL);

	if (!g_dbus_interface_skeleton_export(interface_network, connection,
			NETCONFIG_NETWORK_STATE_PATH, NULL)) {
		ERR("Export with path failed");
	}
}

void state_object_deinit(void)
{
	g_object_unref(netconfigstate);
}
