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
#include <dbus/dbus-glib-lowlevel.h>

#include <vconf.h>
#include <vconf-keys.h>

#include "log.h"
#include "util.h"
#include "netdbus.h"
#include "netsupplicant.h"
#include "wifi-state.h"
#include "wifi-indicator.h"
#include "wifi-ssid-scan.h"
#include "wifi-background-scan.h"
#include "network-state.h"
#include "neterror.h"
#include "wifi.h"

#define SIGNAL_SCAN_DONE		"ScanDone"
#define SIGNAL_BSS_ADDED		"BSSAdded"
#define SIGNAL_PROPERTIES_CHANGED			"PropertiesChanged"

#define CONNMAN_SIGNAL_SERVICES_CHANGED		"ServicesChanged"
#define CONNMAN_SIGNAL_PROPERTY_CHANGED		"PropertyChanged"

#define CONNMAN_MANAGER_SIGNAL_FILTER		"type='signal',interface='net.connman.Manager'"
#define CONNMAN_TECHNOLOGY_SIGNAL_FILTER	"type='signal',interface='net.connman.Technology'"
#define CONNMAN_SERVICE_SIGNAL_FILTER		"type='signal',interface='net.connman.Service'"
#define SUPPLICANT_INTERFACE_SIGNAL_FILTER	"type='signal',interface='fi.w1.wpa_supplicant1.Interface'"


static DBusConnection *signal_connection = NULL;

static char *__netconfig_get_property(DBusMessage *msg, int *prop_value)
{
	DBusMessageIter args, variant;
	char *property = NULL;
	dbus_bool_t data;

	/** read these parameters */
	if (!dbus_message_iter_init(msg, &args)) {
		ERR("Message does not have parameters");
	} else if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING) {
		ERR("Argument is not string");
	} else {
		dbus_message_iter_get_basic(&args, &property);
		dbus_message_iter_next(&args);
		dbus_message_iter_recurse(&args, &variant);
		/* Right now, checking for only 'Powered' property which has
		 * Boolean type values
		 */
		if (dbus_message_iter_get_arg_type(&variant) == DBUS_TYPE_BOOLEAN) {
			dbus_message_iter_get_basic(&variant, &data);
			if (data)
				*prop_value = TRUE;
			else
				*prop_value = FALSE;
		} else {
			*prop_value = FALSE;
		}
	}

	return property;
}

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
		INFO("Wi-Fi Technology %s, property %d", key, value);

		if (g_strcmp0(key, "Powered") == 0) {
			/* Power state */
			if (value == TRUE)
				netconfig_wifi_update_power_state(TRUE);
			else
				netconfig_wifi_update_power_state(FALSE);

			netconfig_set_power_in_progress(FALSE);
			netconfig_check_fm_waiting();
		} else if (g_strcmp0(key, "Connected") == 0) {
			/* Connection state */
		} else if (g_strcmp0(key, "Tethering") == 0) {
			/* Tethering state */
		}
	} else if (g_str_has_prefix(tech,
			CONNMAN_CELLULAR_TECHNOLOGY_PREFIX) == TRUE) {
		/* Cellular technology state */
	}
}

static void __netconfig_wifi_service_state_signal_handler(DBusMessage *msg)
{
	char *sigvalue = NULL;
	char *property = NULL;
	char *service_profile = NULL;
	DBusMessageIter args, variant;

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

				netconfig_set_default_profile(service_profile);

				netconfig_wifi_state_set_service_state(NETCONFIG_WIFI_CONNECTED);

			} else if (g_str_equal(property, "failure") == TRUE ||
					g_str_equal(property, "disconnect") == TRUE ||
					g_str_equal(property, "idle") == TRUE) {
				if (netconfig_get_default_profile() == NULL ||
						netconfig_is_wifi_profile(netconfig_get_default_profile())
						!= TRUE) {
					netconfig_wifi_state_set_service_state(NETCONFIG_WIFI_IDLE);
					return;
				}

				if (g_str_equal(service_profile, netconfig_get_default_profile()) != TRUE)
					return;

				netconfig_set_default_profile(NULL);

				netconfig_wifi_state_set_service_state(NETCONFIG_WIFI_IDLE);

			} else if (g_str_equal(property, "association") == TRUE ||
					g_str_equal(property, "configuration") == TRUE) {
				if (netconfig_get_default_profile() == NULL ||
						netconfig_is_wifi_profile(netconfig_get_default_profile())
						!= TRUE) {
					netconfig_wifi_state_set_service_state(NETCONFIG_WIFI_CONNECTING);
					return;
				}

				if (g_str_equal(service_profile, netconfig_get_default_profile()) != TRUE)
					return;

				netconfig_set_default_profile(NULL);

				netconfig_wifi_state_set_service_state(NETCONFIG_WIFI_CONNECTING);
			}
		} else {
			if (g_str_equal(property, "ready") == TRUE ||
					g_str_equal(property, "online") == TRUE) {
				if (netconfig_get_default_profile() == NULL)
					netconfig_set_default_profile(service_profile);

			} else if (g_str_equal(property, "failure") == TRUE ||
					g_str_equal(property, "disconnect") == TRUE ||
					g_str_equal(property, "idle") == TRUE) {
				if (netconfig_get_default_profile() == NULL)
					return;

				if (g_str_equal(service_profile, netconfig_get_default_profile()) != TRUE)
					return;

				netconfig_set_default_profile(NULL);

			} else if (g_str_equal(property, "association") == TRUE ||
					g_str_equal(property, "configuration") == TRUE) {
				if (netconfig_get_default_profile() == NULL)
					return;

				if (g_str_equal(service_profile, netconfig_get_default_profile()) != TRUE)
					return;

				netconfig_set_default_profile(NULL);
			}
		}
	}
}

static DBusHandlerResult __netconfig_signal_filter_handler(
		DBusConnection *conn, DBusMessage *msg, void *user_data)
{
	char *sigvalue = NULL;

	if (msg == NULL) {
		DBG("Invalid Message. Ignore");
		return DBUS_HANDLER_RESULT_HANDLED;
	}

	if (dbus_message_is_signal(msg, CONNMAN_MANAGER_INTERFACE,
			CONNMAN_SIGNAL_PROPERTY_CHANGED)) {
		/* We have handled this message, don't pass it on */
		return DBUS_HANDLER_RESULT_HANDLED;
	} else if (dbus_message_is_signal(msg, CONNMAN_TECHNOLOGY_INTERFACE,
			CONNMAN_SIGNAL_PROPERTY_CHANGED)) {
		__netconfig_technology_signal_handler(msg);

		return DBUS_HANDLER_RESULT_HANDLED;
	} else if (dbus_message_is_signal(msg, CONNMAN_SERVICE_INTERFACE,
			CONNMAN_SIGNAL_PROPERTY_CHANGED)) {
		__netconfig_wifi_service_state_signal_handler(msg);

		return DBUS_HANDLER_RESULT_HANDLED;
	} else if (dbus_message_is_signal(msg, CONNMAN_MANAGER_INTERFACE,
			CONNMAN_SIGNAL_SERVICES_CHANGED)) {
		DBG("Received CONNMAN_SIGNAL_SERVICES_CHANGED message");
		netconfig_wifi_check_network_notification(msg);

		return DBUS_HANDLER_RESULT_HANDLED;
	} else if (dbus_message_is_signal(msg, SUPPLICANT_INTERFACE ".Interface",
			SIGNAL_PROPERTIES_CHANGED)) {
		dbus_bool_t scanning = FALSE;
		void *property = &scanning;

		if (netconfig_dbus_get_basic_params_array(msg,
				&sigvalue, &property) != TRUE)
			return DBUS_HANDLER_RESULT_HANDLED;

		if (sigvalue == NULL)
			return DBUS_HANDLER_RESULT_HANDLED;

		if (scanning == TRUE)
			netconfig_wifi_set_scanning(TRUE);

		return DBUS_HANDLER_RESULT_HANDLED;
	} else if (dbus_message_is_signal(msg, SUPPLICANT_INTERFACE ".Interface",
			SIGNAL_BSS_ADDED)) {
		if (netconfig_wifi_get_ssid_scan_state() == TRUE)
			netconfig_wifi_bss_added(msg);

		return DBUS_HANDLER_RESULT_HANDLED;
	} else if (dbus_message_is_signal(msg, SUPPLICANT_INTERFACE ".Interface",
			SIGNAL_SCAN_DONE)) {
		netconfig_wifi_set_scanning(FALSE);

		if (netconfig_wifi_get_bgscan_state() != TRUE) {
			if (netconfig_wifi_get_ssid_scan_state() == TRUE)
				netconfig_wifi_notify_ssid_scan_done();
			else
				netconfig_wifi_ssid_scan(NULL);
		}

		return DBUS_HANDLER_RESULT_HANDLED;
	}

	return DBUS_HANDLER_RESULT_NOT_YET_HANDLED;
}

void netconfig_register_signal(void)
{
	DBusConnection *conn = NULL;
	DBusError err;

	DBG("Register DBus signal filters");

	dbus_error_init(&err);
	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (conn == NULL) {
		ERR("Error! Failed to connect to the D-BUS daemon: [%s]",
				err.message);
		dbus_error_free(&err);
		return;
	}

	signal_connection = conn;

	dbus_connection_setup_with_g_main(conn, NULL);

	/* listening to messages from all objects as no path is specified */
	/* see signals from the given interface */
	dbus_bus_add_match(conn, CONNMAN_MANAGER_SIGNAL_FILTER, &err);
	dbus_connection_flush(conn);
	if (dbus_error_is_set(&err)) {
		ERR("Error! Match Error (%s)", err.message);
		dbus_error_free(&err);
		return;
	}

	dbus_bus_add_match(conn, CONNMAN_TECHNOLOGY_SIGNAL_FILTER, &err);
	dbus_connection_flush(conn);
	if (dbus_error_is_set(&err)) {
		ERR("Error! Match Error (%s)", err.message);
		dbus_error_free(&err);
		return;
	}

	dbus_bus_add_match(conn, CONNMAN_SERVICE_SIGNAL_FILTER, &err);
	dbus_connection_flush(conn);
	if (dbus_error_is_set(&err)) {
		ERR("Error! Match Error (%s)", err.message);
		dbus_error_free(&err);
		return;
	}

	dbus_bus_add_match(conn, SUPPLICANT_INTERFACE_SIGNAL_FILTER, &err);
	dbus_connection_flush(conn);
	if (dbus_error_is_set(&err)) {
		ERR("Error! Match Error (%s)", err.message);
		dbus_error_free(&err);
		return;
	}

	if (dbus_connection_add_filter(conn,
			__netconfig_signal_filter_handler, NULL, NULL) == FALSE) {
		ERR("Error! dbus_connection_add_filter() failed");
		return;
	}

	INFO("Successfully register signal filters");
}

void netconfig_deregister_signal(void)
{
	if (signal_connection == NULL) {
		ERR("Error! Already de-registered. Nothing to be done");
		return;
	}

	dbus_connection_remove_filter(signal_connection,
				__netconfig_signal_filter_handler, NULL);
	INFO("Successfully remove DBus signal filters");

	dbus_connection_unref(signal_connection);
	signal_connection = NULL;

	netconfig_wifi_deinit_bgscan();
}
