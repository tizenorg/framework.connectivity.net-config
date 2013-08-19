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
#include <unistd.h>
#include <vconf.h>
#include <vconf-keys.h>
#include <wifi-direct.h>

#include "wifi.h"
#include "log.h"
#include "wifi.h"
#include "util.h"
#include "netdbus.h"
#include "neterror.h"
#include "netconfig.h"
#include "emulator.h"
#include "network-statistics.h"
#include "wifi-background-scan.h"
#include "wifi-power.h"
#include "wifi-state.h"
#include "mdm-private.h"
#include "wifi-agent.h"
#include "wifi-eap-config.h"


#define WLAN_DRIVER_SCRIPT "/usr/bin/wlan.sh"

static gboolean power_in_progress = FALSE;
static gboolean fm_waiting = FALSE;

static gboolean __netconfig_wifi_enable_technology(void)
{
	DBusMessage *reply = NULL;
	char param1[] = "string:Powered";
	char param2[] = "variant:boolean:true";
	char *param_array[] = {NULL, NULL, NULL};

	param_array[0] = param1;
	param_array[1] = param2;

	reply = netconfig_invoke_dbus_method(CONNMAN_SERVICE, CONNMAN_WIFI_TECHNOLOGY_PREFIX,
			CONNMAN_TECHNOLOGY_INTERFACE, "SetProperty", param_array);

	if (reply == NULL) {
		ERR("Error! Request failed");
		return FALSE;
	}

	dbus_message_unref(reply);

	return TRUE;
}

static gboolean __netconfig_wifi_disable_technology(void)
{
	DBusMessage *reply = NULL;
	char param1[] = "string:Powered";
	char param2[] = "variant:boolean:false";
	char *param_array[] = {NULL, NULL, NULL};

	param_array[0] = param1;
	param_array[1] = param2;

	reply = netconfig_invoke_dbus_method(CONNMAN_SERVICE, CONNMAN_WIFI_TECHNOLOGY_PREFIX,
			CONNMAN_TECHNOLOGY_INTERFACE, "SetProperty", param_array);

	if (reply == NULL) {
		ERR("Error! Request failed");
		return FALSE;
	}

	dbus_message_unref(reply);

	return TRUE;
}

static gboolean __netconfig_wifi_load_driver(void)
{
	gboolean rv = FALSE;
	const char *path = WLAN_DRIVER_SCRIPT;
	char *const args[] = { "wlan.sh", "start", NULL };
	char *const envs[] = { NULL };

	if (netconfig_emulator_is_emulated() == TRUE)
		return rv;

	rv = netconfig_execute_file(path, args, envs);
	if (rv != TRUE) {
		DBG("Failed to load wireless device driver");
		return FALSE;
	}

	DBG("Successfully loaded wireless device driver");
	return TRUE;
}

gboolean netconfig_wifi_remove_driver(void)
{
	gboolean rv = FALSE;
	const char *path = WLAN_DRIVER_SCRIPT;
	char *const args[] = { "wlan.sh", "stop", NULL };
	char *const env[] = { NULL };

	if (netconfig_emulator_is_emulated() == TRUE)
		return rv;

	rv = netconfig_execute_file(path, args, env);
	if (rv != TRUE) {
		DBG("Failed to remove wireless device driver");
		return FALSE;
	}

	DBG("Successfully removed wireless device driver");
	return TRUE;
}

static int __netconfig_wifi_try_to_load_driver(void);
static gboolean __netconfig_wifi_try_to_remove_driver(void);

void netconfig_wifi_notify_power_completed(gboolean power_on)
{
	DBusMessage *signal;
	DBusConnection *connection;
	DBusError error;
	char *sig_name;

	if (power_on)
		sig_name = "PowerOnCompleted";
	else
		sig_name = "PowerOffCompleted";

	dbus_error_init(&error);

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
	if (connection == NULL) {
		ERR("Error!!! Failed to get system DBus, error [%s]", error.message);
		dbus_error_free(&error);
		return;
	}

	signal = dbus_message_new_signal(NETCONFIG_WIFI_PATH,
					NETCONFIG_WIFI_INTERFACE, sig_name);
	if (signal == NULL)
		return;

	dbus_connection_send(connection, signal, NULL);

	dbus_message_unref(signal);
	dbus_connection_unref(connection);

	INFO("(%s)", sig_name);
}

static void __netconfig_wifi_direct_state_cb(int error_code,
		wifi_direct_device_state_e device_state, void *user_data)
{
	wifi_direct_unset_device_state_changed_cb();
	wifi_direct_deinitialize();

	if (device_state == WIFI_DIRECT_DEVICE_STATE_DEACTIVATED) {
		if (__netconfig_wifi_try_to_load_driver() < 0) {
			power_in_progress = FALSE;

			/* TODO: error report */

			return;
		}
	}
}

static gboolean __netconfig_wifi_direct_power_off(void)
{
	DBG("Wi-Fi direct is turning off");

	if (wifi_direct_initialize() < 0)
		return FALSE;

	if (wifi_direct_set_device_state_changed_cb(
			__netconfig_wifi_direct_state_cb, NULL) < 0)
		return FALSE;

	if (wifi_direct_deactivate() < 0)
		return FALSE;

	return TRUE;
}

static int __netconfig_wifi_try_to_load_driver(void)
{
	if (netconfig_is_wifi_allowed() != TRUE)
		return -EPERM;

	if (netconfig_is_wifi_tethering_on() == TRUE) {
		/* TODO: Wi-Fi tethering turns off here */
		/* return TRUE; */
		return -EBUSY;
	}

	if (netconfig_is_wifi_direct_on() == TRUE) {
		if (__netconfig_wifi_direct_power_off() == TRUE) {
			power_in_progress = TRUE;
			return -EINPROGRESS;
		} else
			return -EBUSY;
	}

	if (__netconfig_wifi_load_driver() != TRUE) {
		netconfig_wifi_remove_driver();

		return -EIO;
	}

	if (__netconfig_wifi_enable_technology() != TRUE) {
		netconfig_wifi_remove_driver();
		return -EIO;
	}

	power_in_progress = TRUE;

	return 0;
}

static gboolean __netconfig_wifi_try_to_remove_driver(void)
{
	netconfig_wifi_device_picker_service_stop();

	netconfig_wifi_statistics_update_powered_off();

	if (__netconfig_wifi_disable_technology() != TRUE)
		return FALSE;

	power_in_progress = TRUE;

	return TRUE;
}

static void __netconfig_wifi_airplane_mode(keynode_t* node,
		void* user_data)
{
	int value = 0;
	int wifi_state = 0;
	static gboolean powered_off_by_flightmode = FALSE;

	if (power_in_progress) {
		fm_waiting = TRUE;
		return;
	}

	fm_waiting = FALSE;

	vconf_get_bool(VCONFKEY_TELEPHONY_FLIGHT_MODE, &value);
	vconf_get_int(VCONFKEY_WIFI_STATE, &wifi_state);

	DBG("flight mode %s", value > 0 ? "ON" : "OFF");
	DBG("Wi-Fi state %d, Wi-Fi was off by flight mode %s",
			wifi_state, powered_off_by_flightmode == TRUE ? "Yes" : "No");

	if (value > 0) {
		/* flight mode enabled */
		if (wifi_state == VCONFKEY_WIFI_OFF)
			return;

		DBG("Turning Wi-Fi off");

		__netconfig_wifi_try_to_remove_driver();

		powered_off_by_flightmode = TRUE;
	} else if (value == 0) {
		/* flight mode disabled */
		if (wifi_state > VCONFKEY_WIFI_OFF)
			return;

		if (powered_off_by_flightmode != TRUE)
			return;

		__netconfig_wifi_try_to_load_driver();

		powered_off_by_flightmode = FALSE;
	} else
		DBG("Invalid value (%d)", value);
}

static void __netconfig_wifi_pm_state_mode(keynode_t* node,
		void* user_data)
{
	int value = -1;
	int wifi_state = 0;
	static int prev_state = VCONFKEY_PM_STATE_NORMAL;

	/*** vconf-keys.h ***
	 * 		VCONFKEY_PM_STATE_NORMAL = 1,
	 * 		VCONFKEY_PM_STATE_LCDDIM,
	 * 		VCONFKEY_PM_STATE_LCDOFF,
	 * 		VCONFKEY_PM_STATE_SLEEP
	 */

	if(vconf_get_int(VCONFKEY_WIFI_STATE, &wifi_state) == 0) {
		DBG("wifi state : %d (0 off / 1 on / 2 connected)", wifi_state);
		if(wifi_state <= VCONFKEY_WIFI_OFF)
			return;
	}

	if(vconf_get_int(VCONFKEY_PM_STATE, &value) < 0) {
		ERR("VCONFKEY_PM_STATE get failed");
		return;
	}

	DBG("Old state: %d, current: %d", prev_state, value);

	if((value == VCONFKEY_PM_STATE_NORMAL) && (prev_state >= VCONFKEY_PM_STATE_LCDOFF)) {
		DBG("PM state : Wake UP!");

		netconfig_wifi_bgscan_stop();
		netconfig_wifi_bgscan_start();
	}

	prev_state = value;
}

void netconfig_set_power_in_progress(gboolean in_progress)
{
	power_in_progress = in_progress;
}

void netconfig_check_fm_waiting(void)
{
	if (fm_waiting)
		__netconfig_wifi_airplane_mode(NULL, NULL);
}

void netconfig_wifi_power_configuration(void)
{
	int wifi_last_power_state = 0;

	vconf_notify_key_changed(VCONFKEY_TELEPHONY_FLIGHT_MODE,
			__netconfig_wifi_airplane_mode, NULL);

	vconf_notify_key_changed(VCONFKEY_PM_STATE,
			__netconfig_wifi_pm_state_mode, NULL);

	vconf_get_int(VCONF_WIFI_LAST_POWER_STATE, &wifi_last_power_state);

	if (wifi_last_power_state == WIFI_POWER_ON) {
		DBG("Turn Wi-Fi on automatically");

		__netconfig_wifi_try_to_load_driver();
	}
}

gboolean netconfig_iface_wifi_load_driver(NetconfigWifi *wifi, GError **error)
{
	DBG("Wi-Fi power on requested");

	g_return_val_if_fail(wifi != NULL, FALSE);

	int err;

	if (netconfig_is_wifi_allowed() != TRUE) {
		netconfig_error_security_restricted(error);

		return FALSE;
	}

	if (power_in_progress) {
		netconfig_error_wifi_driver_failed(error);
		return FALSE;
	}

	err = __netconfig_wifi_try_to_load_driver();
	if (err < 0) {
		if (err == -EINPROGRESS)
			netconfig_error_wifi_load_inprogress(error);
		else
			netconfig_error_wifi_driver_failed(error);

		return FALSE;
	}

	return TRUE;
}

gboolean netconfig_iface_wifi_remove_driver(NetconfigWifi *wifi, GError **error)
{
	DBG("Wi-Fi power off requested");

	g_return_val_if_fail(wifi != NULL, FALSE);

	if (power_in_progress) {
		netconfig_error_wifi_driver_failed(error);
		return FALSE;
	}

	if (__netconfig_wifi_try_to_remove_driver() != TRUE) {
		netconfig_error_wifi_driver_failed(error);

		return FALSE;
	}

	return TRUE;
}
