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

#include <stdio.h>
#include <string.h>
#include <vconf.h>
#include <vconf-keys.h>

#include "log.h"
#include "util.h"
#include "netdbus.h"
#include "neterror.h"
#include "wifi-wps.h"
#include "wifi-agent.h"
#include "wifi-power.h"
#include "wifi-state.h"
#include "netsupplicant.h"
#include "network-state.h"
#include "cellular-state.h"
#include "signal-handler.h"
#include "wifi-ssid-scan.h"
#include "wifi-background-scan.h"

#if defined TIZEN_DEBUG_DISABLE
#include "wifi-dump.h"
#endif

#define DBUS_SERVICE_DBUS			"org.freedesktop.DBus"
#define DBUS_INTERFACE_DBUS			"org.freedesktop.DBus"
#define SIGNAL_INTERFACE_REMOVED		"InterfaceRemoved"
#define SIGNAL_SCAN_DONE			"ScanDone"
#define SIGNAL_BSS_ADDED			"BSSAdded"
#define SIGNAL_PROPERTIES_CHANGED		"PropertiesChanged"
#define SIGNAL_PROPERTIES_DRIVER_HANGED		"DriverHanged"
#define SIGNAL_PROPERTIES_SESSION_OVERLAPPED	"SessionOverlapped"
#define CONNMAN_SIGNAL_SERVICES_CHANGED		"ServicesChanged"
#define CONNMAN_SIGNAL_PROPERTY_CHANGED		"PropertyChanged"
#define CONNMAN_SIGNAL_NAME_CHANGED		"NameOwnerChanged"

#define MAX_SIG_LEN 64
#define TOTAL_CONN_SIGNALS 3

typedef enum {
	SIG_INTERFACE_REMOVED = 0,
	SIG_PROPERTIES_CHANGED,
	SIG_BSS_ADDED,
	SIG_SCAN_DONE,
	SIG_DRIVER_HANGED,
	SIG_SESSION_OVERLAPPED,
	SIG_MAX
} SuppSigArrayIndex;

static int conn_subscription_ids[TOTAL_CONN_SIGNALS] = {0};
static const char supplicant_signals[SIG_MAX][MAX_SIG_LEN] = {
		SIGNAL_INTERFACE_REMOVED,
		SIGNAL_PROPERTIES_CHANGED,
		SIGNAL_BSS_ADDED,
		SIGNAL_SCAN_DONE,
		SIGNAL_PROPERTIES_DRIVER_HANGED,
		SIGNAL_PROPERTIES_SESSION_OVERLAPPED,
};

static int supp_subscription_ids[SIG_MAX] = {0};
static int dumpservice_subscription_id = 0;

typedef void (*supplicant_signal_cb)(GDBusConnection *conn,
		const gchar *name, const gchar *path, const gchar *interface,
		const gchar *sig, GVariant *param, gpointer user_data);
typedef void (*connman_signal_cb)(GDBusConnection *conn,
		const gchar *name, const gchar *path, const gchar *interface,
		const gchar *sig, GVariant *param, gpointer user_data);

static void _technology_signal_cb(GDBusConnection *conn,
		const gchar *name, const gchar *path, const gchar *interface,
		const gchar *sig, GVariant *param, gpointer user_data)
{
	gchar *key = NULL;
	gboolean value = FALSE;
	GVariant *var = NULL;

	if (param == NULL)
		return;

	if (g_str_has_prefix(path, CONNMAN_WIFI_TECHNOLOGY_PREFIX) == TRUE) {
		g_variant_get(param, "(sv)", &key, &var);
		if (g_strcmp0(key, "Powered") == 0) {
			/* Power state */
			value = g_variant_get_boolean(var);
			if (value == TRUE) {
				wifi_state_update_power_state(TRUE);
			} else {
				wifi_state_update_power_state(FALSE);
			}
		} else if (g_strcmp0(key, "Connected") == 0) {
			/* Connection state */
			wifi_state_set_tech_state(NETCONFIG_WIFI_TECH_CONNECTED);
		} else if (g_strcmp0(key, "Tethering") == 0) {
			/* Tethering state */
			wifi_state_set_tech_state(NETCONFIG_WIFI_TECH_TETHERED);
		}
		if (key)
			g_free(key);
		if (var)
			g_variant_unref(var);
	}
}

static void _service_signal_cb(GDBusConnection *conn,
		const gchar *name, const gchar *path,
		const gchar *interface, const gchar *sig, GVariant *param, gpointer user_data)
{
	gchar *sigvalue = NULL;
	gchar *property;
	GVariant *variant = NULL, *var;
	GVariantIter *iter;
	const gchar *value = NULL;

	if (path == NULL || param == NULL)
		goto done;

	g_variant_get(param, "(sv)", &sigvalue, &variant);
	if (sigvalue == NULL)
		goto done;

	if (g_strcmp0(sig, CONNMAN_SIGNAL_PROPERTY_CHANGED) != 0) {
		goto done;
	}

	if (g_strcmp0(sigvalue, "State") == 0) {
		g_variant_get(variant, "s", &property);

		DBG("[%s] %s", property, path);
		if (netconfig_is_wifi_profile(path) == TRUE) {
			int wifi_state = 0;

			vconf_get_int(VCONFKEY_WIFI_STATE, &wifi_state);
			if (wifi_state == VCONFKEY_WIFI_OFF)
				goto done;

			if (g_strcmp0(property, "ready") == 0 || g_strcmp0(property, "online") == 0) {
				if (wifi_state >= VCONFKEY_WIFI_CONNECTED)
					goto done;

				netconfig_update_default_profile(path);

				wifi_state_set_service_state(NETCONFIG_WIFI_CONNECTED);

			} else if (g_strcmp0(property, "failure") == 0 || g_strcmp0(property, "disconnect") == 0 || g_strcmp0(property, "idle") == 0) {
				if (netconfig_get_default_profile() == NULL ||
						netconfig_is_wifi_profile(netconfig_get_default_profile())
						!= TRUE) {
					if (g_strcmp0(property, "failure") == 0)
						wifi_state_set_service_state(NETCONFIG_WIFI_FAILURE);
					else
						wifi_state_set_service_state(NETCONFIG_WIFI_IDLE);
					goto done;
				}

				if (g_strcmp0(path, netconfig_get_default_profile()) != 0)
					goto done;

				netconfig_update_default_profile(NULL);

				if (g_strcmp0(property, "failure") == 0)
					wifi_state_set_service_state(NETCONFIG_WIFI_FAILURE);
				else
					wifi_state_set_service_state(NETCONFIG_WIFI_IDLE);

			} else if (g_strcmp0(property, "association") == 0 || g_strcmp0(property, "configuration") == 0) {
				if (netconfig_get_default_profile() == NULL ||
						netconfig_is_wifi_profile(netconfig_get_default_profile()) != TRUE) {
					if (g_strcmp0(property, "association") == 0)
						wifi_state_set_service_state(NETCONFIG_WIFI_ASSOCIATION);
					else
						wifi_state_set_service_state(NETCONFIG_WIFI_CONFIGURATION);
					goto done;
				}

				if (g_strcmp0(path, netconfig_get_default_profile()) != 0)
					goto done;

				netconfig_update_default_profile(NULL);

				if (g_strcmp0(property, "association") == 0)
					wifi_state_set_service_state(NETCONFIG_WIFI_ASSOCIATION);
				else
					wifi_state_set_service_state(NETCONFIG_WIFI_CONFIGURATION);

			}
		} else {
			if (g_strcmp0(property, "ready") == 0 || g_strcmp0(property, "online") == 0) {
				if (netconfig_get_default_profile() == NULL) {
					if(!netconfig_is_cellular_profile(path)) {
						netconfig_update_default_profile(path);
					} else {
						if (netconfig_is_cellular_internet_profile(path)) {
							netconfig_update_default_profile(path);
						}
					}
				}

				if (netconfig_is_cellular_profile(path) && netconfig_is_cellular_internet_profile(path))
					cellular_state_set_service_state(NETCONFIG_CELLULAR_ONLINE);

			} else if (g_strcmp0(property, "failure") == 0 || g_strcmp0(property, "disconnect") == 0 || g_strcmp0(property, "idle") == 0) {
				if (netconfig_get_default_profile() == NULL)
					goto done;

				if (netconfig_is_cellular_profile(path) && netconfig_is_cellular_internet_profile(path))
					cellular_state_set_service_state(NETCONFIG_CELLULAR_IDLE);

				if (g_strcmp0(path, netconfig_get_default_profile()) != 0)
					goto done;

				netconfig_update_default_profile(NULL);
			} else if (g_strcmp0(property, "association") == 0 || 	g_strcmp0(property, "configuration") == 0) {
				if (netconfig_get_default_profile() == NULL)
					goto done;

				if (netconfig_is_cellular_profile(path) && netconfig_is_cellular_internet_profile(path))
					cellular_state_set_service_state(NETCONFIG_CELLULAR_CONNECTING);

				if (g_strcmp0(path, netconfig_get_default_profile()) != 0)
					goto done;

				netconfig_update_default_profile(NULL);
			}
		}
	} else if (g_strcmp0(sigvalue, "Proxy") == 0) {
		if (netconfig_is_wifi_profile(path) != TRUE || g_strcmp0(path, netconfig_get_default_profile()) != 0)
			goto done;

		if (!g_variant_type_equal(variant, G_VARIANT_TYPE_ARRAY))
			goto done;

		g_variant_get(variant, "a{sv}", &iter);
		while (g_variant_iter_loop(iter, "{sv}", &property, &var)) {
			if (g_strcmp0(property, "Servers") == 0) {
				GVariantIter *iter_sub = NULL;

				g_variant_get(var, "as", &iter_sub);
				g_variant_iter_loop(iter_sub, "s", &value);
				g_variant_iter_free(iter_sub);

				DBG("Proxy - [%s]", value);
				vconf_set_str(VCONFKEY_NETWORK_PROXY, value);

				g_free(property);
				g_variant_unref(var);
				break;
			} else if (g_strcmp0(property, "Method") == 0) {
				value = g_variant_get_string(var, NULL);
				DBG("Method - [%s]", value);

				if (g_strcmp0(value, "direct") == 0)
					vconf_set_str(VCONFKEY_NETWORK_PROXY, "");

				g_free(property);
				g_variant_unref(var);
				break;
			}
		}

		g_variant_iter_free(iter);
	} else if (g_strcmp0(sigvalue, "Error") == 0) {
		g_variant_get(variant, "s", &property);
		INFO("[%s] Property : %s", sigvalue, property);
	}
done:
	if (sigvalue)
		g_free(sigvalue);

	if (variant)
		g_variant_unref(variant);

	return;
}

static void _dbus_name_changed_cb(GDBusConnection *conn,
		const gchar *Name, const gchar *path, const gchar *interface,
		const gchar *sig, GVariant *param, gpointer user_data)
{
	gchar *name = NULL;
	gchar *old = NULL;
	gchar *new = NULL;

	if (param == NULL)
		return;

	g_variant_get(param, "(sss)", &name, &old, &new);

	if (g_strcmp0(name, CONNMAN_SERVICE) == 0 && *new == '\0') {
		DBG("ConnMan destroyed: name %s, old %s, new %s", name, old, new);

		connman_register_agent();
	}
	if (name)
		g_free(name);
	if (old)
		g_free(old);
	if (new)
		g_free(new);

	return;
}

static void _supplicant_interface_removed(GDBusConnection *conn,
		const gchar *name, const gchar *path, const gchar *interface,
		const gchar *sig, GVariant *param, gpointer user_data)
{
	DBG("Interface removed handling!");
	if (netconfig_wifi_is_wps_enabled() == TRUE)
		netconfig_wifi_wps_signal_scanaborted();

	return;
}

static void _supplicant_properties_changed(GDBusConnection *conn,
		const gchar *name, const gchar *path, const gchar *interface,
		const gchar *sig, GVariant *param, gpointer user_data)
{
	DBG("Properties changed handling!");
	gchar *key;
	GVariantIter *iter;
	GVariant *variant;
	gboolean scanning = FALSE;

	if (param == NULL)
		return;

	g_variant_get(param, "(a{sv})", &iter);
	while (g_variant_iter_loop(iter, "{sv}", &key, &variant)) {
		if (g_strcmp0(key, "Scanning") == 0) {
			scanning = g_variant_get_boolean(variant);
			if (scanning == TRUE)
				netconfig_wifi_set_scanning(TRUE);

			g_variant_unref(variant);
			g_free(key);
			break;
		}
	}

	g_variant_iter_free(iter);

	return;
}

static void _supplicant_bss_added(GDBusConnection *conn,
		const gchar *name, const gchar *path, const gchar *interface,
		const gchar *sig, GVariant *param, gpointer user_data)
{
	DBG("BSS added handling!");
	if (wifi_ssid_scan_get_state() == TRUE)
		wifi_ssid_scan_add_bss(param);
	else
		wifi_state_set_bss_found(TRUE);

	return;
}

static void _supplicant_scan_done(GDBusConnection *conn,
		const gchar *name, const gchar *path, const gchar *interface,
		const gchar *sig, GVariant *param, gpointer user_data)
{
	DBG("Scan Done handling!");
	netconfig_wifi_set_scanning(FALSE);

	if (netconfig_wifi_is_wps_enabled() == TRUE) {
		netconfig_wifi_wps_signal_scandone();
		if (wifi_state_get_technology_state() < NETCONFIG_WIFI_TECH_POWERED)
			return;
	}

	if (netconfig_wifi_get_bgscan_state() != TRUE) {
		if (wifi_ssid_scan_get_state() == TRUE)
			wifi_ssid_scan_emit_scan_completed();
		else
			wifi_ssid_scan(NULL);
	} else {
		if (wifi_state_get_technology_state() >=
				NETCONFIG_WIFI_TECH_POWERED)
			netconfig_wifi_bgscan_start(FALSE);

		wifi_start_timer_network_notification();
	}

	return;
}

static void _supplicant_driver_hanged(GDBusConnection *conn,
		const gchar *name, const gchar *path, const gchar *interface,
		const gchar *sig, GVariant *param, gpointer user_data)
{
	DBG("Driver Hanged handling!");
	ERR("Critical. Wi-Fi firmware crashed");

	wifi_power_recover_firmware();

	return;
}

static void _supplicant_session_overlapped(GDBusConnection *conn,
		const gchar *name, const gchar *path, const gchar *interface,
		const gchar *sig, GVariant *param, gpointer user_data)
{
	DBG("Driver session overlapped handling!");
	ERR("WPS PBC SESSION OVERLAPPED");
#if defined TIZEN_WEARABLE
	wc_launch_syspopup(WC_POPUP_TYPE_SESSION_OVERLAPPED);
#else
	netconfig_send_message_to_net_popup("WPS Error",
					"wps session overlapped", "popup", NULL);
#endif
}

static supplicant_signal_cb supplicant_cbs[SIG_MAX] = {
		_supplicant_interface_removed,
		_supplicant_properties_changed,
		_supplicant_bss_added,
		_supplicant_scan_done,
		_supplicant_driver_hanged,
		_supplicant_session_overlapped
};

#if defined TIZEN_DEBUG_DISABLE
static void __netconfig_dumpservice_handler(GDBusConnection *conn,
		const gchar *name, const gchar *path, const gchar *interface,
		const gchar *sig, GVariant *param, gpointer user_data)
{
	int mode;
	gchar *signal_path = NULL;

	if (param == NULL)
		return;

	g_variant_get(param, "(io)", &mode, &signal_path);
	DBG("Path: %s and mode: %d", signal_path, mode);
	netconfig_dump_log(path);
	if (signal_path)
		g_free(signal_path);

	return;
}
#endif

void register_gdbus_signal(void)
{
	GDBusConnection *connection = NULL;
	const char *interface = NULL;
	SuppSigArrayIndex sig;
	connection = netdbus_get_connection();

	if (connection == NULL) {
		ERR("Failed to get GDbus Connection");
		return;
	}

	/* listening to messages from all objects as no path is specified */
	/* see signals from the given interface */
	conn_subscription_ids[0] = g_dbus_connection_signal_subscribe(
			connection,
			CONNMAN_SERVICE,
			CONNMAN_TECHNOLOGY_INTERFACE,
			NULL,
			NULL,
			NULL,
			G_DBUS_SIGNAL_FLAGS_NONE,
			_technology_signal_cb,
			NULL,
			NULL);

	conn_subscription_ids[1] = g_dbus_connection_signal_subscribe(
			connection,
			CONNMAN_SERVICE,
			CONNMAN_SERVICE_INTERFACE,
			CONNMAN_SIGNAL_PROPERTY_CHANGED,
			NULL,
			NULL,
			G_DBUS_SIGNAL_FLAGS_NONE,
			_service_signal_cb,
			NULL,
			NULL);

	conn_subscription_ids[2] = g_dbus_connection_signal_subscribe(
			connection,
			DBUS_SERVICE_DBUS,
			DBUS_INTERFACE_DBUS,
			CONNMAN_SIGNAL_NAME_CHANGED,
			NULL,
			CONNMAN_SERVICE,
			G_DBUS_SIGNAL_FLAGS_NONE,
			_dbus_name_changed_cb,
			NULL,
			NULL);

	INFO("Successfully register connman DBus signal filters");

	for (sig = SIG_INTERFACE_REMOVED; sig < SIG_MAX; sig++) {
		/*
		 * For SIG_INTERFACE_REMOVED INTERFACE_ADDED
		 */
		interface = (sig == SIG_INTERFACE_REMOVED) ?
				SUPPLICANT_INTERFACE : SUPPLICANT_IFACE_INTERFACE;

		supp_subscription_ids[sig] = g_dbus_connection_signal_subscribe(
				connection,
				SUPPLICANT_SERVICE,
				interface,
				supplicant_signals[sig],
				NULL,
				NULL,
				G_DBUS_SIGNAL_FLAGS_NONE,
				supplicant_cbs[sig],
				NULL,
				NULL);
	}

	INFO("Successfully register Supplicant DBus signal filters");

#if defined TIZEN_DEBUG_DISABLE
	dumpservice_subscription_id = g_dbus_connection_signal_subscribe(
			connection,
			/*
			 * Sender => For testing purpose made NULL
			 *WPA_SUPPLICANT,
			 */
			NULL,
			DUMP_SERVICE_INTERFACE,
			DUMP_SIGNAL,
			NULL,
			NULL,
			G_DBUS_SIGNAL_FLAGS_NONE,
			__netconfig_dumpservice_handler,
			NULL,
			NULL);

	INFO("Successfully register Dumpservice DBus signal filter");
#endif
	/* In case ConnMan precedes this signal register,
	 * net-config should update the default connected profile.
	 */
	netconfig_update_default();
}

void deregister_gdbus_signal(void)
{
	GDBusConnection *connection = NULL;
	int signal;
	SuppSigArrayIndex sig;
	connection = netdbus_get_connection();
	if (!connection) {
		ERR("Already de-registered. Nothing to be done");
		return;
	}

	for (signal = 0; signal < TOTAL_CONN_SIGNALS; signal++) {
		if (conn_subscription_ids[signal]) {
			g_dbus_connection_signal_unsubscribe(connection,
						conn_subscription_ids[signal]);
		}
	}

	for (sig = SIG_INTERFACE_REMOVED; sig < SIG_MAX; sig++) {
		if (supp_subscription_ids[sig]) {
			g_dbus_connection_signal_unsubscribe(connection,
						supp_subscription_ids[sig]);
		}
	}

	g_dbus_connection_signal_unsubscribe(connection,
			dumpservice_subscription_id);
}
