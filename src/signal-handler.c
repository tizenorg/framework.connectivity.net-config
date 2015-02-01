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
#include <dbus/dbus-glib-lowlevel.h>

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
#include "mdm-private.h"
#include "netsupplicant.h"
#include "network-state.h"
#include "cellular-state.h"
#include "signal-handler.h"
#include "wifi-ssid-scan.h"
#include "wifi-background-scan.h"

#define SIGNAL_INTERFACE_REMOVED			"InterfaceRemoved"
#define SIGNAL_SCAN_DONE					"ScanDone"
#define SIGNAL_BSS_ADDED					"BSSAdded"
#define SIGNAL_PROPERTIES_CHANGED			"PropertiesChanged"
#define SIGNAL_PROPERTIES_DRIVER_HANGED		"DriverHanged"
#define SIGNAL_PROPERTIES_SESSION_OVERLAPPED	"SessionOverlapped"

#define CONNMAN_SIGNAL_SERVICES_CHANGED		"ServicesChanged"
#define CONNMAN_SIGNAL_PROPERTY_CHANGED		"PropertyChanged"

#define CONNMAN_TECHNOLOGY_SIGNAL_FILTER \
	"type='signal',interface='"CONNMAN_TECHNOLOGY_INTERFACE"'"

#define CONNMAN_SERVICE_STATE_SIGNAL_FILTER \
	"type='signal',interface='"CONNMAN_SERVICE_INTERFACE \
	"',member='PropertyChanged',arg0='State'"

#define CONNMAN_SERVICE_PROXY_SIGNAL_FILTER \
	"type='signal',interface='"CONNMAN_SERVICE_INTERFACE \
	"',member='PropertyChanged',arg0='Proxy'"

#define SUPPLICANT_INTERFACE_REMOVED_SIGNAL_FILTER \
	"type='signal',interface='"SUPPLICANT_INTERFACE \
	"',member='"SIGNAL_INTERFACE_REMOVED"'"

#define SUPPLICANT_INTERFACE_PROPERTIESCHANGED_SIGNAL_FILTER \
	"type='signal',interface='"SUPPLICANT_IFACE_INTERFACE \
	"',member='"SIGNAL_PROPERTIES_CHANGED"'"

#define SUPPLICANT_INTERFACE_BSSADDED_SIGNAL_FILTER \
	"type='signal',interface='"SUPPLICANT_IFACE_INTERFACE \
	"',member='"SIGNAL_BSS_ADDED"'"

#define SUPPLICANT_INTERFACE_SCANDONE_SIGNAL_FILTER \
	"type='signal',interface='"SUPPLICANT_IFACE_INTERFACE \
	"',member='"SIGNAL_SCAN_DONE"'"

#define SUPPLICANT_INTERFACE_DRIVERHANGED_SIGNAL_FILTER \
	"type='signal',interface='"SUPPLICANT_IFACE_INTERFACE \
	"',member='"SIGNAL_PROPERTIES_DRIVER_HANGED"'"

#define SUPPLICANT_INTERFACE_SESSIONOVERLAPPED_SIGNAL_FILTER \
	"type='signal',interface='"SUPPLICANT_IFACE_INTERFACE \
	"',member='"SIGNAL_PROPERTIES_SESSION_OVERLAPPED"'"

#define CONNMAN_SERVICE_NAMECHANGED_SIGNAL_FILTER \
	"type='signal',sender='"DBUS_SERVICE_DBUS \
	"',interface='"DBUS_INTERFACE_DBUS \
	"',member='NameOwnerChanged',path='/org/freedesktop/DBus'" \
	",arg0='"CONNMAN_SERVICE"'"


static DBusConnection *signal_connection = NULL;

static void __netconfig_technology_signal_handler(DBusMessage *msg)
{
	char *key = NULL;
	const char *tech = NULL;
	dbus_bool_t value = FALSE;

	if (netconfig_dbus_get_basic_params_string(msg,
			&key, DBUS_TYPE_BOOLEAN, &value) != TRUE)
		return;

	tech = dbus_message_get_path(msg);
	if (key == NULL || tech == NULL)
		return;

	if (g_str_has_prefix(tech, CONNMAN_WIFI_TECHNOLOGY_PREFIX) == TRUE) {
		if (g_strcmp0(key, "Powered") == 0) {
			/* Power state */
			if (value == TRUE) {
				netconfig_wifi_update_power_state(TRUE);
			} else {
				netconfig_wifi_update_power_state(FALSE);
			}
		} else if (g_strcmp0(key, "Connected") == 0) {
			/* Connection state */
			netconfig_wifi_state_set_technology_state(
								NETCONFIG_WIFI_TECH_CONNECTED);
		} else if (g_strcmp0(key, "Tethering") == 0) {
			/* Tethering state */
			netconfig_wifi_state_set_technology_state(
								NETCONFIG_WIFI_TECH_TETHERED);
		}
	} else if (g_str_has_prefix(tech,
			CONNMAN_CELLULAR_TECHNOLOGY_PREFIX) == TRUE) {
		/* Cellular technology state */
	}
}

static void __netconfig_service_signal_handler(DBusMessage *msg)
{
	char *sigvalue = NULL;
	char *property = NULL;
	char *service_profile = NULL;
	DBusMessageIter args, variant, iter1, iter2, iter3, iter4;
	const char *value = NULL;

	service_profile = (char *)dbus_message_get_path(msg);
	if (service_profile == NULL)
		return;

	dbus_message_iter_init(msg, &args);
	dbus_message_iter_get_basic(&args, &sigvalue);
	if (sigvalue == NULL)
		return;

	if (g_str_equal(sigvalue, "State") == TRUE) {
		dbus_message_iter_next(&args);
		dbus_message_iter_recurse(&args, &variant);
		dbus_message_iter_get_basic(&variant, &property);

		DBG("[%s] %s", property, service_profile);
		if (netconfig_is_wifi_profile(service_profile) == TRUE) {
			int wifi_state = 0;

			vconf_get_int(VCONFKEY_WIFI_STATE, &wifi_state);
			if (wifi_state == VCONFKEY_WIFI_OFF)
				return;

			if (g_str_equal(property, "ready") == TRUE ||
					g_str_equal(property, "online") == TRUE) {
				if (wifi_state >= VCONFKEY_WIFI_CONNECTED)
					return;

				netconfig_update_default_profile(service_profile);

				netconfig_wifi_state_set_service_state(NETCONFIG_WIFI_CONNECTED);

				netconfig_check_allowed_ap(service_profile);

			} else if (g_str_equal(property, "failure") == TRUE ||
					g_str_equal(property, "disconnect") == TRUE ||
					g_str_equal(property, "idle") == TRUE) {
				if (netconfig_get_default_profile() == NULL ||
						netconfig_is_wifi_profile(netconfig_get_default_profile())
						!= TRUE) {
					if (g_str_equal(property, "failure") == TRUE)
						netconfig_wifi_state_set_service_state(
											NETCONFIG_WIFI_FAILURE);
					else
						netconfig_wifi_state_set_service_state(
											NETCONFIG_WIFI_IDLE);
					return;
				}

				if (g_str_equal(service_profile, netconfig_get_default_profile())
						!= TRUE)
					return;

				netconfig_update_default_profile(NULL);

				if (g_str_equal(property, "failure") == TRUE)
					netconfig_wifi_state_set_service_state(
										NETCONFIG_WIFI_FAILURE);
				else
					netconfig_wifi_state_set_service_state(
										NETCONFIG_WIFI_IDLE);

			} else if (g_str_equal(property, "association") == TRUE ||
					g_str_equal(property, "configuration") == TRUE) {
				if (netconfig_get_default_profile() == NULL ||
						netconfig_is_wifi_profile(netconfig_get_default_profile()) != TRUE) {
					if (g_str_equal(property, "association") == TRUE)
						netconfig_wifi_state_set_service_state(
											NETCONFIG_WIFI_ASSOCIATION);
					else
						netconfig_wifi_state_set_service_state(
											NETCONFIG_WIFI_CONFIGURATION);
					return;
				}

				if (g_str_equal(service_profile, netconfig_get_default_profile()) != TRUE)
					return;

				netconfig_update_default_profile(NULL);

				if (g_str_equal(property, "association") == TRUE)
					netconfig_wifi_state_set_service_state(
										NETCONFIG_WIFI_ASSOCIATION);
				else
					netconfig_wifi_state_set_service_state(
										NETCONFIG_WIFI_CONFIGURATION);

			}
		} else {
			if (g_str_equal(property, "ready") == TRUE ||
					g_str_equal(property, "online") == TRUE) {
				if (netconfig_get_default_profile() == NULL)
					netconfig_update_default_profile(service_profile);

				if (netconfig_is_cellular_profile(service_profile) == TRUE)
					netconfig_cellular_state_set_service_state(NETCONFIG_CELLULAR_ONLINE);
			} else if (g_str_equal(property, "failure") == TRUE ||
					g_str_equal(property, "disconnect") == TRUE ||
					g_str_equal(property, "idle") == TRUE) {
				if (netconfig_get_default_profile() == NULL)
					return;

				if (netconfig_is_cellular_profile(service_profile) == TRUE)
					netconfig_cellular_state_set_service_state(NETCONFIG_CELLULAR_IDLE);

				if (g_str_equal(service_profile, netconfig_get_default_profile()) != TRUE)
					return;

				netconfig_update_default_profile(NULL);
			} else if (g_str_equal(property, "association") == TRUE ||
					g_str_equal(property, "configuration") == TRUE) {
				if (netconfig_get_default_profile() == NULL)
					return;

				if (netconfig_is_cellular_profile(service_profile) == TRUE)
					netconfig_cellular_state_set_service_state(NETCONFIG_CELLULAR_IDLE);

				if (g_str_equal(service_profile, netconfig_get_default_profile()) != TRUE)
					return;

				netconfig_update_default_profile(NULL);
			}
		}
	} else if (g_str_equal(sigvalue, "Proxy") == TRUE) {
		dbus_message_iter_next(&args);
		dbus_message_iter_recurse(&args, &variant);

		if (netconfig_is_wifi_profile(service_profile) != TRUE ||
				g_strcmp0(service_profile, netconfig_get_default_profile()) != 0)
			return;

		if (dbus_message_iter_get_arg_type(&variant) != DBUS_TYPE_ARRAY)
			return;

		dbus_message_iter_recurse(&variant, &iter1);
		while (dbus_message_iter_get_arg_type(&iter1) ==
				DBUS_TYPE_DICT_ENTRY) {
			dbus_message_iter_recurse(&iter1, &iter2);
			dbus_message_iter_get_basic(&iter2, &property);

			if (g_strcmp0(property, "Servers") == 0) {
				dbus_message_iter_next(&iter2);
				dbus_message_iter_recurse(&iter2, &iter3);

				if (dbus_message_iter_get_arg_type(&iter3) !=
						DBUS_TYPE_ARRAY)
					return;

				dbus_message_iter_recurse(&iter3, &iter4);
				if (dbus_message_iter_get_arg_type(&iter4) !=
						DBUS_TYPE_STRING)
					return;

				dbus_message_iter_get_basic(&iter4, &value);
				DBG("Proxy - [%s]", value);

				vconf_set_str(VCONFKEY_NETWORK_PROXY, value);
				break;
			} else if (g_strcmp0(property, "Method") == 0) {
				dbus_message_iter_next(&iter2);
				dbus_message_iter_recurse(&iter2, &iter3);

				if (dbus_message_iter_get_arg_type(&iter3) !=
						DBUS_TYPE_STRING)
					return;

				dbus_message_iter_get_basic(&iter3, &value);
				DBG("Method - [%s]", value);

				if (g_strcmp0(value, "direct") == 0)
					vconf_set_str(VCONFKEY_NETWORK_PROXY, "");

				break;
			}
			dbus_message_iter_next(&iter1);
		}
	}
}

static void __netconfig_dbus_name_changed_signal_handler(DBusMessage *msg)
{
	char *name, *old, *new;

	dbus_message_get_args(msg, NULL, DBUS_TYPE_STRING, &name,
			DBUS_TYPE_STRING, &old, DBUS_TYPE_STRING, &new);

	if (g_strcmp0(name, CONNMAN_SERVICE) == 0 && *new == '\0') {
		DBG("ConnMan destroyed: name %s, old %s, new %s", name, old, new);

		netconfig_agent_register();
	}
}

static DBusHandlerResult __netconfig_signal_filter_handler(
		DBusConnection *conn, DBusMessage *msg, void *user_data)
{
	if (msg == NULL) {
		DBG("Invalid Message. Ignore");
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	if (dbus_message_is_signal(msg, CONNMAN_TECHNOLOGY_INTERFACE,
			CONNMAN_SIGNAL_PROPERTY_CHANGED)) {
		__netconfig_technology_signal_handler(msg);

		return DBUS_HANDLER_RESULT_HANDLED;
	} else if (dbus_message_is_signal(msg, CONNMAN_SERVICE_INTERFACE,
			CONNMAN_SIGNAL_PROPERTY_CHANGED)) {
		__netconfig_service_signal_handler(msg);

		return DBUS_HANDLER_RESULT_HANDLED;
	} else if (dbus_message_is_signal(msg, SUPPLICANT_INTERFACE,
			SIGNAL_INTERFACE_REMOVED)) {
		if (netconfig_wifi_is_wps_enabled() == TRUE)
			netconfig_wifi_wps_signal_scanaborted();

		return DBUS_HANDLER_RESULT_HANDLED;
	} else if (dbus_message_is_signal(msg, SUPPLICANT_INTERFACE ".Interface",
			SIGNAL_PROPERTIES_CHANGED)) {
		dbus_bool_t scanning = FALSE;
		void *property = &scanning;

		if (netconfig_dbus_get_basic_params_array(msg,
							"Scanning", &property) == TRUE) {
			if (scanning == TRUE)
				netconfig_wifi_set_scanning(TRUE);
		}

		return DBUS_HANDLER_RESULT_HANDLED;
	} else if (dbus_message_is_signal(msg, SUPPLICANT_INTERFACE ".Interface",
			SIGNAL_BSS_ADDED)) {
		if (netconfig_wifi_get_ssid_scan_state() == TRUE)
			netconfig_wifi_bss_added(msg);
		else
			netconfig_wifi_set_bss_found(TRUE);

		return DBUS_HANDLER_RESULT_HANDLED;
	} else if (dbus_message_is_signal(msg, SUPPLICANT_INTERFACE ".Interface",
			SIGNAL_SCAN_DONE)) {
		netconfig_wifi_set_scanning(FALSE);

		if (netconfig_wifi_is_wps_enabled() == TRUE) {
			netconfig_wifi_wps_signal_scandone();
			if (netconfig_wifi_state_get_technology_state() <
									NETCONFIG_WIFI_TECH_POWERED)
				return DBUS_HANDLER_RESULT_HANDLED;
		}

		if (netconfig_wifi_get_bgscan_state() != TRUE) {
			if (netconfig_wifi_get_ssid_scan_state() == TRUE)
				netconfig_wifi_notify_ssid_scan_done();
			else
				netconfig_wifi_ssid_scan(NULL);
		} else {
			if (netconfig_wifi_state_get_technology_state() >=
										NETCONFIG_WIFI_TECH_POWERED)
				netconfig_wifi_bgscan_start(FALSE);

			netconfig_wifi_start_timer_network_notification();
		}

		return DBUS_HANDLER_RESULT_HANDLED;
	} else if (dbus_message_is_signal(msg, SUPPLICANT_INTERFACE ".Interface",
			SIGNAL_PROPERTIES_DRIVER_HANGED)) {
		ERR("Critical. Wi-Fi firmware crashed");

		netconfig_wifi_recover_firmware();

		return DBUS_HANDLER_RESULT_HANDLED;
	} else if (dbus_message_is_signal(msg, SUPPLICANT_INTERFACE ".Interface",
			SIGNAL_PROPERTIES_SESSION_OVERLAPPED)) {
		ERR("WPS PBC SESSION OVERLAPPED");
#if !defined TIZEN_WEARABLE
	netconfig_send_message_to_net_popup("WPS Error",
						"wps session overlapped", "popup", NULL);
#endif
		return DBUS_HANDLER_RESULT_HANDLED;
	} else if (dbus_message_is_signal(msg, DBUS_INTERFACE_DBUS,
			"NameOwnerChanged")) {
		__netconfig_dbus_name_changed_signal_handler(msg);

		return DBUS_HANDLER_RESULT_HANDLED;
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

void netconfig_register_signal(void)
{
	DBusError err;
	DBusConnection *conn = NULL;

	dbus_error_init(&err);
	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (conn == NULL) {
		ERR("Failed to get system bus [%s]", err.message);
		dbus_error_free(&err);
		return;
	}

	signal_connection = conn;

	dbus_connection_setup_with_g_main(conn, NULL);

	/* listening to messages from all objects as no path is specified */
	/* see signals from the given interface */
	dbus_bus_add_match(conn, CONNMAN_TECHNOLOGY_SIGNAL_FILTER, &err);
	dbus_connection_flush(conn);
	if (dbus_error_is_set(&err)) {
		ERR("Match error (%s)", err.message);
		dbus_error_free(&err);
		return;
	}

	dbus_bus_add_match(conn, CONNMAN_SERVICE_STATE_SIGNAL_FILTER, &err);
	dbus_connection_flush(conn);
	if (dbus_error_is_set(&err)) {
		ERR("Match error (%s)", err.message);
		dbus_error_free(&err);
		return;
	}

	dbus_bus_add_match(conn, CONNMAN_SERVICE_PROXY_SIGNAL_FILTER, &err);
	dbus_connection_flush(conn);
	if (dbus_error_is_set(&err)) {
		ERR("Match error (%s)", err.message);
		dbus_error_free(&err);
		return;
	}

	dbus_bus_add_match(conn, SUPPLICANT_INTERFACE_REMOVED_SIGNAL_FILTER, &err);
	dbus_connection_flush(conn);
	if (dbus_error_is_set(&err)) {
		ERR("Match error (%s)", err.message);
		dbus_error_free(&err);
		return;
	}

	dbus_bus_add_match(conn,
			SUPPLICANT_INTERFACE_PROPERTIESCHANGED_SIGNAL_FILTER, &err);
	dbus_connection_flush(conn);
	if (dbus_error_is_set(&err)) {
		ERR("Match error (%s)", err.message);
		dbus_error_free(&err);
		return;
	}

	dbus_bus_add_match(conn, SUPPLICANT_INTERFACE_BSSADDED_SIGNAL_FILTER, &err);
	dbus_connection_flush(conn);
	if (dbus_error_is_set(&err)) {
		ERR("Match error (%s)", err.message);
		dbus_error_free(&err);
		return;
	}

	dbus_bus_add_match(conn, SUPPLICANT_INTERFACE_SCANDONE_SIGNAL_FILTER, &err);
	dbus_connection_flush(conn);
	if (dbus_error_is_set(&err)) {
		ERR("Match error (%s)", err.message);
		dbus_error_free(&err);
		return;
	}

	dbus_bus_add_match(conn,
			SUPPLICANT_INTERFACE_DRIVERHANGED_SIGNAL_FILTER, &err);
	dbus_connection_flush(conn);
	if (dbus_error_is_set(&err)) {
		ERR("Match error (%s)", err.message);
		dbus_error_free(&err);
		return;
	}

	dbus_bus_add_match(conn,
			SUPPLICANT_INTERFACE_SESSIONOVERLAPPED_SIGNAL_FILTER, &err);
	dbus_connection_flush(conn);
	if (dbus_error_is_set(&err)) {
		ERR("Match error (%s)", err.message);
		dbus_error_free(&err);
		return;
	}

	dbus_bus_add_match(conn, CONNMAN_SERVICE_NAMECHANGED_SIGNAL_FILTER, &err);
	dbus_connection_flush(conn);
	if (dbus_error_is_set(&err)) {
		ERR("Match error (%s)", err.message);
		dbus_error_free(&err);
		return;
	}

	if (dbus_connection_add_filter(conn,
			__netconfig_signal_filter_handler, NULL, NULL) == FALSE) {
		ERR("Error! dbus_connection_add_filter() failed");
		return;
	}

	INFO("Successfully register DBus signal filters");

	/* In case ConnMan precedes this signal register,
	 * net-config should update the default connected profile.
	 */
	netconfig_update_default();
}

void netconfig_deregister_signal(void)
{
	if (signal_connection == NULL) {
		ERR("Already de-registered. Nothing to be done");
		return;
	}

	dbus_connection_remove_filter(signal_connection,
				__netconfig_signal_filter_handler, NULL);
	INFO("Successfully remove DBus signal filters");

	dbus_connection_unref(signal_connection);
	signal_connection = NULL;
}
