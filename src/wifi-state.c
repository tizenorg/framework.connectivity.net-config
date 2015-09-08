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

#include <aul.h>
#include <vconf.h>
#include <vconf-keys.h>
#include <journal/wifi.h>

#include "log.h"
#include "util.h"
#include "netdbus.h"
#include "wifi-state.h"
#include "wifi-power.h"
#include "netsupplicant.h"
#include "network-state.h"
#include "wifi-indicator.h"
#include "wifi-powersave.h"
#include "network-statistics.h"
#include "wifi-background-scan.h"

#define NETCONFIG_NETWORK_NOTIFICATION_TIMEOUT	15 * 1000

static gboolean new_bss_found = FALSE;
static guint network_noti_timer_id = 0;

static enum netconfig_wifi_service_state
	wifi_service_state = NETCONFIG_WIFI_UNKNOWN;
static enum netconfig_wifi_tech_state
	wifi_technology_state = NETCONFIG_WIFI_TECH_UNKNOWN;

static GSList *notifier_list = NULL;


static void __netconfig_pop_wifi_connected_poppup(const char *ssid)
{
	bundle *b = NULL;

	if (ssid == NULL)
		return;

	b = bundle_create();

	bundle_add(b, "_SYSPOPUP_TITLE_", "Network connection popup");
	bundle_add(b, "_SYSPOPUP_TYPE_", "notification");
	bundle_add(b, "_SYSPOPUP_CONTENT_", "wifi connected");
	bundle_add(b, "_AP_NAME_", ssid);

	DBG("Launch Wi-Fi connected alert network popup");
	aul_launch_app("net.netpopup", b);

	bundle_free(b);
}

static void __netconfig_wifi_state_connected_activation(void)
{
	/* Add activation of services when Wi-Fi is connected */
	bundle *b = NULL;

	b = bundle_create();
	aul_launch_app("org.tizen.keepit-service-standby", b);
	bundle_free(b);

	/* logd service checks Wi-Fi state */
	journal_wifi_network_connected();
}

static void __netconfig_wifi_state_disconnected_activation(void)
{
	/* Add activation of services when Wi-Fi is disconnected */

	/* logd service checks Wi-Fi state */
	journal_wifi_network_disconnected();
}

static void __netconfig_wifi_state_powered_activation(gboolean powered)
{
	if (powered == TRUE) {
		/* Add activation when Wi-Fi is powered on */

		/* logd service checks Wi-Fi power state */
		journal_wifi_on();
	} else {
		/* Add activation when Wi-Fi is powered off */

		/* logd service checks Wi-Fi power state */
		journal_wifi_off();
	}
}

static void __netconfig_wifi_set_essid(void)
{
	const char *essid_name = NULL;
	const char *wifi_profile = netconfig_get_default_profile();

	if (netconfig_wifi_state_get_service_state() != NETCONFIG_WIFI_CONNECTED)
		return;

	if (wifi_profile == NULL ||
			netconfig_is_wifi_profile(wifi_profile) != TRUE) {
		ERR("Can't get Wi-Fi profile");
		return;
	}

	essid_name = netconfig_wifi_get_connected_essid(wifi_profile);
	if (essid_name == NULL) {
		ERR("Can't get Wi-Fi name");
		return;
	}

	netconfig_set_vconf_str(VCONFKEY_WIFI_CONNECTED_AP_NAME, essid_name);

	__netconfig_pop_wifi_connected_poppup(essid_name);
}

static void __netconfig_wifi_unset_essid(void)
{
	netconfig_set_vconf_str(VCONFKEY_WIFI_CONNECTED_AP_NAME, "");
}

static gboolean __netconfig_is_wifi_profile_available(void)
{
	DBusMessage *message = NULL;
	DBusMessageIter iter, array;
	int ret = FALSE;

	message = netconfig_invoke_dbus_method(CONNMAN_SERVICE,
			CONNMAN_MANAGER_PATH, CONNMAN_MANAGER_INTERFACE,
			"GetServices", NULL);
	if (message == NULL) {
		ERR("Failed to get service list");
		return FALSE;
	}

	dbus_message_iter_init(message, &iter);
	dbus_message_iter_recurse(&iter, &array);

	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_STRUCT) {
		DBusMessageIter entry;
		const char *obj = NULL;

		dbus_message_iter_recurse(&array, &entry);
		dbus_message_iter_get_basic(&entry, &obj);

		if (obj == NULL || netconfig_is_wifi_profile(obj) == FALSE) {
			dbus_message_iter_next(&array);
			continue;
		}

		ret = TRUE;
		goto done;
	}

done:
	dbus_message_unref(message);

	return ret;
}

static char *__netconfig_wifi_get_connman_favorite_service(void)
{
	char *favorite_service = NULL;
	DBusMessage *message = NULL;
	DBusMessageIter iter, array;

	message = netconfig_invoke_dbus_method(CONNMAN_SERVICE,
			CONNMAN_MANAGER_PATH, CONNMAN_MANAGER_INTERFACE,
			"GetServices", NULL);
	if (message == NULL) {
		ERR("Failed to get service list");
		return NULL;
	}

	dbus_message_iter_init(message, &iter);
	dbus_message_iter_recurse(&iter, &array);

	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_STRUCT) {
		DBusMessageIter entry;
		DBusMessageIter dict;
		const char *obj = NULL;

		dbus_message_iter_recurse(&array, &entry);
		dbus_message_iter_get_basic(&entry, &obj);

		if (obj == NULL || netconfig_is_wifi_profile(obj) == FALSE) {
			dbus_message_iter_next(&array);
			continue;
		}

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &dict);

		while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
			DBusMessageIter entry, variant;
			const char *key = NULL;
			dbus_bool_t value;

			dbus_message_iter_recurse(&dict, &entry);
			dbus_message_iter_get_basic(&entry, &key);

			if (g_str_equal(key, "Favorite") != TRUE) {
				dbus_message_iter_next(&dict);
				continue;
			}

			dbus_message_iter_next(&entry);
			dbus_message_iter_recurse(&entry, &variant);

			dbus_message_iter_get_basic(&variant, &value);

			if (value)
				favorite_service = g_strdup(obj);

			goto done;
		}

		dbus_message_iter_next(&array);
	}

done:
	dbus_message_unref(message);

	return favorite_service;
}

static void __netconfig_wifi_state_changed(
		enum netconfig_wifi_service_state state)
{
	GSList *list;

	for (list = notifier_list; list; list = list->next) {
		struct netconfig_wifi_state_notifier *notifier = list->data;

		if (notifier->netconfig_wifi_state_changed != NULL)
			notifier->netconfig_wifi_state_changed(state, notifier->user_data);
	}
}

void netconfig_wifi_set_bss_found(const gboolean found)
{
	if (found != new_bss_found)
		new_bss_found = found;
}

gboolean netconfig_wifi_is_bss_found(void)
{
	return new_bss_found;
}

static void __netconfig_wifi_state_set_power_save(gboolean power_save)
{
	dbus_bool_t result;
	const char *if_path;
	GList *input_args = NULL;
	static gboolean old_state = TRUE;

	struct dbus_input_arguments args_disable[2] = {
			{DBUS_TYPE_STRING, "POWERMODE 1"},
			{DBUS_TYPE_INVALID, NULL}
	};
	struct dbus_input_arguments args_enable[2] = {
			{DBUS_TYPE_STRING, "POWERMODE 0"},
			{DBUS_TYPE_INVALID, NULL}
	};

	if (old_state == power_save)
		return;

	if_path = netconfig_wifi_get_supplicant_interface();
	if (if_path == NULL) {
		ERR("Fail to get wpa_supplicant DBus path");
		return;
	}

	if (power_save)
		input_args = setup_input_args(input_args, args_enable);
	else
		input_args = setup_input_args(input_args, args_disable);

	result = netconfig_supplicant_invoke_dbus_method_nonblock(
				SUPPLICANT_SERVICE, if_path,
				SUPPLICANT_INTERFACE ".Interface", "Driver", input_args,
				NULL);
	if (result == FALSE)
		ERR("Fail to set power save mode POWERMODE %d", power_save);
	else
		old_state = power_save;

	g_list_free(input_args);
}

static void __netconfig_wifi_state_set_power_lock(gboolean power_lock)
{
	int ret = 0;
	DBusMessage *reply;
	char state[] = "string:lcdoff";
	char flag[] = "string:staycurstate";
	char standby[] = "string:NULL";
	char timeout[] = "int32:0";
	char sleepmargin[] = "string:sleepmargin";
	char *param_array[] = { NULL, NULL, NULL, NULL, NULL };

	const char *lockstate = "lockstate";
	const char *unlockstate = "unlockstate";
	static gboolean old_state = FALSE;
	const char *lock_method;

	if (old_state == power_lock)
		return;

	if (power_lock == TRUE) {
		/* deviced power lock enable */
		param_array[0] = state;
		param_array[1] = flag;
		param_array[2] = standby;
		param_array[3] = timeout;

		lock_method = lockstate;
	} else {
		/* deviced power lock disable */
		param_array[0] = state;
		param_array[1] = sleepmargin;

		lock_method = unlockstate;
	}

	reply = netconfig_invoke_dbus_method(
			"org.tizen.system.deviced",
			"/Org/Tizen/System/DeviceD/Display",
			"org.tizen.system.deviced.display",
			lock_method,
			param_array);
	if (reply == NULL)
		return;

	dbus_message_get_args(reply, NULL, DBUS_TYPE_INT32,
							&ret, DBUS_TYPE_INVALID);
	if (ret < 0)
		ERR("Failed to set power lock %s with ret %d",
				power_lock == TRUE ? "enable" : "disable", ret);
	else
		old_state = power_lock;

	dbus_message_unref(reply);
}

void netconfig_wifi_state_set_service_state(
		enum netconfig_wifi_service_state new_state)
{
	static gboolean dhcp_stage = FALSE;
	enum netconfig_wifi_service_state old_state = wifi_service_state;

	if (old_state == new_state)
		return;

	wifi_service_state = new_state;
	DBG("Wi-Fi state %d ==> %d", old_state, new_state);

	/* During DHCP, temporarily disable Wi-Fi power saving */
	if ((old_state < NETCONFIG_WIFI_ASSOCIATION ||
			old_state == NETCONFIG_WIFI_FAILURE) &&
			new_state == NETCONFIG_WIFI_CONFIGURATION) {
		__netconfig_wifi_state_set_power_lock(TRUE);
		__netconfig_wifi_state_set_power_save(FALSE);
		dhcp_stage = TRUE;
	} else if (dhcp_stage == TRUE) {
		__netconfig_wifi_state_set_power_lock(FALSE);
		__netconfig_wifi_state_set_power_save(TRUE);
		dhcp_stage = FALSE;
	}

	if (new_state == NETCONFIG_WIFI_CONNECTED) {
		netconfig_send_notification_to_net_popup(NETCONFIG_DEL_FOUND_AP_NOTI, NULL);

		netconfig_set_vconf_int(VCONFKEY_WIFI_STATE, VCONFKEY_WIFI_CONNECTED);
		netconfig_set_vconf_int(VCONFKEY_NETWORK_WIFI_STATE,
									VCONFKEY_NETWORK_WIFI_CONNECTED);

		__netconfig_wifi_set_essid();

		netconfig_wifi_indicator_start();
	} else if (old_state == NETCONFIG_WIFI_CONNECTED) {
		netconfig_send_notification_to_net_popup(NETCONFIG_DEL_PORTAL_NOTI, NULL);

		__netconfig_wifi_unset_essid();

		netconfig_set_vconf_int (VCONFKEY_WIFI_STATE, VCONFKEY_WIFI_UNCONNECTED);
		netconfig_set_vconf_int(VCONFKEY_NETWORK_WIFI_STATE,
									VCONFKEY_NETWORK_WIFI_NOT_CONNECTED);

		netconfig_wifi_indicator_stop();

		netconfig_wifi_set_bgscan_pause(FALSE);

		netconfig_wifi_bgscan_stop();
		netconfig_wifi_bgscan_start(TRUE);
	}

	__netconfig_wifi_state_changed(new_state);

	if (new_state == NETCONFIG_WIFI_CONNECTED){
		__netconfig_wifi_state_connected_activation();
	} else if (old_state == NETCONFIG_WIFI_CONNECTED)
		__netconfig_wifi_state_disconnected_activation();
}

enum netconfig_wifi_service_state
netconfig_wifi_state_get_service_state(void)
{
	return wifi_service_state;
}

void netconfig_wifi_state_set_technology_state(
		enum netconfig_wifi_tech_state new_state)
{
	enum netconfig_wifi_tech_state old_state = wifi_technology_state;

	if (old_state == new_state)
		return;

	wifi_technology_state = new_state;

	DBG("Wi-Fi technology state %d ==> %d", old_state, new_state);
}

enum netconfig_wifi_tech_state netconfig_wifi_state_get_technology_state(void)
{
	DBusMessage *message = NULL;
	DBusMessageIter iter, array;
	enum netconfig_wifi_tech_state ret = NETCONFIG_WIFI_TECH_OFF;
	gboolean wifi_tech_powered = FALSE;
	gboolean wifi_tech_connected = FALSE;

	if (wifi_technology_state > NETCONFIG_WIFI_TECH_UNKNOWN)
		return wifi_technology_state;

	message = netconfig_invoke_dbus_method(CONNMAN_SERVICE,
			CONNMAN_MANAGER_PATH, CONNMAN_MANAGER_INTERFACE,
			"GetTechnologies", NULL);
	if (message == NULL) {
		ERR("Failed to get Wi-Fi technology state");
		return NETCONFIG_WIFI_TECH_UNKNOWN;
	}

	dbus_message_iter_init(message, &iter);
	dbus_message_iter_recurse(&iter, &array);

	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_STRUCT) {
		DBusMessageIter entry, dict;
		const char *path;

		dbus_message_iter_recurse(&array, &entry);
		dbus_message_iter_get_basic(&entry, &path);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &dict);

		if (path == NULL ||
				g_str_equal(path, CONNMAN_WIFI_TECHNOLOGY_PREFIX) == FALSE) {
			dbus_message_iter_next(&array);
			continue;
		}

		while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
			DBusMessageIter entry1, value1;
			const char *key, *sdata;
			dbus_bool_t data;

			dbus_message_iter_recurse(&dict, &entry1);
			dbus_message_iter_get_basic(&entry1, &key);

			dbus_message_iter_next(&entry1);
			dbus_message_iter_recurse(&entry1, &value1);

			if (dbus_message_iter_get_arg_type(&value1) ==
					DBUS_TYPE_BOOLEAN) {
				dbus_message_iter_get_basic(&value1, &data);
				DBG("key-[%s] - %s", key, data ? "True" : "False");

				if (strcmp(key, "Powered") == 0 && data) {
					wifi_tech_powered = TRUE;
				} else if (strcmp(key, "Connected") == 0 && data) {
					wifi_tech_connected = TRUE;
				} else if (strcmp(key, "Tethering") == 0 && data) {
					/* For further use */
				}
			} else if (dbus_message_iter_get_arg_type(&value1) ==
					DBUS_TYPE_STRING) {
				dbus_message_iter_get_basic(&value1, &sdata);
				DBG("%s", sdata);
			}

			dbus_message_iter_next(&dict);
		}

		dbus_message_iter_next(&array);
	}

	dbus_message_unref(message);

	if (wifi_tech_powered == TRUE)
		ret = NETCONFIG_WIFI_TECH_POWERED;

	if (wifi_tech_connected == TRUE)
		ret = NETCONFIG_WIFI_TECH_CONNECTED;

	wifi_technology_state = ret;

	return wifi_technology_state;
}

void netconfig_wifi_notify_power_failed(void)
{
	DBusMessage *signal;
	DBusConnection *connection = NULL;
	DBusError error;
	char *sig_name = "PowerOperationFailed";

	dbus_error_init(&error);

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
	if (connection == NULL) {
		ERR("Failed to get system DBus, error [%s]", error.message);
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
}

void netconfig_wifi_notify_power_completed(gboolean power_on)
{
	DBusMessage *signal;
	DBusConnection *connection = NULL;
	DBusError error;
	char *sig_name = NULL;

	if (power_on)
		sig_name = "PowerOnCompleted";
	else
		sig_name = "PowerOffCompleted";

	dbus_error_init(&error);

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
	if (connection == NULL) {
		ERR("Failed to get system DBus, error [%s]", error.message);
		dbus_error_free(&error);
		return;
	}

	signal = dbus_message_new_signal(NETCONFIG_WIFI_PATH,
							NETCONFIG_WIFI_INTERFACE, sig_name);
	if (signal == NULL)
		return;

	dbus_connection_send(connection, signal, NULL);

	DBG("Successfully sent signal [%s]", sig_name);

	dbus_message_unref(signal);
	dbus_connection_unref(connection);
}

static void __netconfig_notification_value_changed_cb(
		keynode_t *node, void *user_data)
{
	int value = -1;

	if (vconf_get_int(VCONFKEY_WIFI_ENABLE_QS, &value) < 0) {
		return;
	}

	if (value == VCONFKEY_WIFI_QS_DISABLE) {
		netconfig_send_notification_to_net_popup(NETCONFIG_DEL_FOUND_AP_NOTI,
				NULL);
	}
}

static void __netconfig_register_network_notification(void)
{
	vconf_notify_key_changed(VCONFKEY_WIFI_ENABLE_QS,
			__netconfig_notification_value_changed_cb, NULL);
}

static void __netconfig_deregister_network_notification(void)
{
	vconf_ignore_key_changed(VCONFKEY_WIFI_ENABLE_QS,
			__netconfig_notification_value_changed_cb);
}

void netconfig_wifi_update_power_state(gboolean powered)
{
	enum netconfig_wifi_tech_state wifi_tech_state;

	/* It's automatically updated by signal-handler
	 * DO NOT update manually
	 * It includes Wi-Fi state configuration
	 */
	wifi_tech_state = netconfig_wifi_state_get_technology_state();

	if (powered == TRUE) {
		if (wifi_tech_state < NETCONFIG_WIFI_TECH_POWERED &&
						netconfig_is_wifi_tethering_on() != TRUE) {
			DBG("Wi-Fi turned on or waken up from power-save mode");

			netconfig_wifi_state_set_technology_state(
										NETCONFIG_WIFI_TECH_POWERED);

			netconfig_wifi_notify_power_completed(TRUE);

			netconfig_wifi_device_picker_service_start();

			netconfig_set_vconf_int(VCONF_WIFI_LAST_POWER_STATE,
										VCONFKEY_WIFI_UNCONNECTED);
			netconfig_set_vconf_int(VCONFKEY_WIFI_STATE,
										VCONFKEY_WIFI_UNCONNECTED);
			netconfig_set_vconf_int(VCONFKEY_NETWORK_WIFI_STATE,
										VCONFKEY_NETWORK_WIFI_NOT_CONNECTED);

			netconfig_wifi_bgscan_stop();
			netconfig_wifi_bgscan_start(TRUE);

			/* Add callback to track change in notification setting */
			__netconfig_register_network_notification();
		}
	} else if (wifi_tech_state > NETCONFIG_WIFI_TECH_OFF) {
		DBG("Wi-Fi turned off or in power-save mode");

		netconfig_wifi_state_set_technology_state(
										NETCONFIG_WIFI_TECH_WPS_ONLY);

		netconfig_wifi_device_picker_service_stop();

		netconfig_wifi_disable_technology_state_by_only_connman_signal();
		netconfig_wifi_driver_and_supplicant(FALSE);

		netconfig_wifi_notify_power_completed(FALSE);

		netconfig_set_vconf_int(VCONF_WIFI_LAST_POWER_STATE, VCONFKEY_WIFI_OFF);
		netconfig_set_vconf_int(VCONFKEY_WIFI_STATE, VCONFKEY_WIFI_OFF);
		netconfig_set_vconf_int(VCONFKEY_NETWORK_WIFI_STATE,
										VCONFKEY_NETWORK_WIFI_OFF);

		netconfig_wifi_set_bgscan_pause(FALSE);
		netconfig_wifi_bgscan_stop();

		netconfig_wifi_set_bss_found(FALSE);

		/* Inform net-popup to remove the wifi found notification */
		netconfig_send_notification_to_net_popup(NETCONFIG_DEL_FOUND_AP_NOTI, NULL);
		netconfig_send_notification_to_net_popup(NETCONFIG_DEL_PORTAL_NOTI, NULL);

		__netconfig_deregister_network_notification();
	}

	__netconfig_wifi_state_powered_activation(powered);
}

char *netconfig_wifi_get_favorite_service(void)
{
	return __netconfig_wifi_get_connman_favorite_service();
}

static gboolean __netconfig_wifi_check_network_notification(gpointer data)
{
	int qs_enable = 0, ug_state = 0;
	static gboolean check_again = FALSE;

	enum netconfig_wifi_tech_state wifi_tech_state;
	enum netconfig_wifi_service_state wifi_service_state;

#if defined TIZEN_WEARABLE
	/* In case of wearable device, no need to notify available Wi-Fi APs */
	return FALSE;
#endif

	wifi_tech_state = netconfig_wifi_state_get_technology_state();
	if (wifi_tech_state < NETCONFIG_WIFI_TECH_POWERED) {
		DBG("Wi-Fi off or WPS only supported[%d]", wifi_tech_state);
		goto cleanup;
	}

	wifi_service_state = netconfig_wifi_state_get_service_state();
	if (wifi_service_state == NETCONFIG_WIFI_CONNECTED) {
		DBG("Service state is connected");
		goto cleanup;
	} else if (wifi_service_state == NETCONFIG_WIFI_ASSOCIATION ||
		wifi_service_state == NETCONFIG_WIFI_CONFIGURATION) {
		DBG("Service state is connecting (check again : %d)", check_again);
		if (!check_again) {
			check_again = TRUE;
			return TRUE;
		} else
			check_again = FALSE;
	}

	if (__netconfig_is_wifi_profile_available() == FALSE) {
		netconfig_send_notification_to_net_popup(
		NETCONFIG_DEL_FOUND_AP_NOTI, NULL);
		goto cleanup;
	}

	vconf_get_int(VCONFKEY_WIFI_ENABLE_QS, &qs_enable);
	if (qs_enable != VCONFKEY_WIFI_QS_ENABLE) {
		DBG("qs_enable != VCONFKEY_WIFI_QS_ENABLE");
		goto cleanup;
	}

	vconf_get_int(VCONFKEY_WIFI_UG_RUN_STATE, &ug_state);
	if (ug_state == VCONFKEY_WIFI_UG_RUN_STATE_ON_FOREGROUND) {
		goto cleanup;
	}

	netconfig_send_notification_to_net_popup(NETCONFIG_ADD_FOUND_AP_NOTI, NULL);

	netconfig_wifi_set_bss_found(FALSE);

cleanup:
	netconfig_stop_timer(&network_noti_timer_id);
	return FALSE;
}

void netconfig_wifi_start_timer_network_notification(void)
{
	netconfig_start_timer(NETCONFIG_NETWORK_NOTIFICATION_TIMEOUT, 
		__netconfig_wifi_check_network_notification, NULL, &network_noti_timer_id);
}

void netconfig_wifi_state_notifier_cleanup(void)
{
	g_slist_free_full(notifier_list, NULL);
}

void netconfig_wifi_state_notifier_register(
		struct netconfig_wifi_state_notifier *notifier)
{
	DBG("register notifier");

	notifier_list = g_slist_append(notifier_list, notifier);
}

void netconfig_wifi_state_notifier_unregister(
		struct netconfig_wifi_state_notifier *notifier)
{
	DBG("un-register notifier");

	notifier_list = g_slist_remove_all(notifier_list, notifier);
}
