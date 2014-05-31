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

#include "log.h"
#include "util.h"
#include "netdbus.h"
#include "network-state.h"
#include "network-statistics.h"
#include "wifi-state.h"
#include "wifi-indicator.h"
#include "wifi-background-scan.h"

static int profiles_count = 0;

static enum netconfig_wifi_service_state
	wifi_service_state = NETCONFIG_WIFI_UNKNOWN;

static GSList *notifier_list = NULL;


static void __netconfig_wifi_set_profiles_count(const int count)
{
	profiles_count = count;
}

static int __netconfig_wifi_get_profiles_count(void)
{
	return profiles_count;
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

	vconf_set_str(VCONFKEY_WIFI_CONNECTED_AP_NAME, essid_name);
}

static void __netconfig_wifi_unset_essid(void)
{
	vconf_set_str(VCONFKEY_WIFI_CONNECTED_AP_NAME, "");
}

static GSList *__netconfig_wifi_state_get_service_profiles(DBusMessage *message)
{
	GSList *service_profiles = NULL;
	DBusMessageIter iter, dict;

	dbus_message_iter_init(message, &iter);
	dbus_message_iter_recurse(&iter, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_STRUCT) {
		DBusMessageIter entry;
		const char *object_path = NULL;

		dbus_message_iter_recurse(&dict, &entry);
		dbus_message_iter_get_basic(&entry, &object_path);

		if (object_path == NULL) {
			dbus_message_iter_next(&dict);
			continue;
		}

		if (netconfig_is_wifi_profile(object_path) == TRUE)
			service_profiles = g_slist_append(service_profiles,
					g_strdup(object_path));

		dbus_message_iter_next(&dict);
	}

	return service_profiles;
}

static char *__netconfig_wifi_get_connman_favorite_service(void)
{
	char *favorite_service = NULL;
	DBusMessage *message = NULL;
	GSList *service_profiles = NULL;
	GSList *list = NULL;

	message = netconfig_invoke_dbus_method(CONNMAN_SERVICE,
			CONNMAN_MANAGER_PATH, CONNMAN_MANAGER_INTERFACE,
			"GetServices", NULL);
	if (message == NULL) {
		ERR("Failed to get service list");
		return NULL;
	}

	/* Get service profiles from ConnMan Manager */
	service_profiles = __netconfig_wifi_state_get_service_profiles(message);
	dbus_message_unref(message);

	for (list = service_profiles; list != NULL; list = list->next) {
		char *profile_path = list->data;
		DBusMessageIter iter, array;

		if (favorite_service != NULL)
			break;

		message = netconfig_invoke_dbus_method(CONNMAN_SERVICE,
				profile_path, CONNMAN_SERVICE_INTERFACE, "GetProperties", NULL);

		if (message == NULL) {
			ERR("Failed to get service information of %s", profile_path);
			continue;
		}

		dbus_message_iter_init(message, &iter);
		dbus_message_iter_recurse(&iter, &array);

		while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_DICT_ENTRY) {
			DBusMessageIter entry, variant;
			const char *key = NULL;
			dbus_bool_t value;

			dbus_message_iter_recurse(&array, &entry);
			dbus_message_iter_get_basic(&entry, &key);

			dbus_message_iter_next(&entry);
			dbus_message_iter_recurse(&entry, &variant);

			if (g_str_equal(key, "Favorite") != TRUE) {
				dbus_message_iter_next(&array);
				continue;
			}

			dbus_message_iter_get_basic(&variant, &value);

			if (value)
				favorite_service = g_strdup(profile_path);

			break;
		}

		dbus_message_unref(message);
	}

	g_slist_free(service_profiles);

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

void netconfig_wifi_state_set_service_state(
		enum netconfig_wifi_service_state new_state)
{
	enum netconfig_wifi_service_state old_state = wifi_service_state;

	if (old_state == new_state)
		return;

	wifi_service_state = new_state;
	DBG("Wi-Fi state %d ==> %d", old_state, new_state);

	if (new_state == NETCONFIG_WIFI_CONNECTED) {
		netconfig_del_wifi_found_notification();

		vconf_set_int(VCONFKEY_WIFI_STATE, VCONFKEY_WIFI_CONNECTED);
		vconf_set_int(VCONFKEY_NETWORK_WIFI_STATE, VCONFKEY_NETWORK_WIFI_CONNECTED);

		__netconfig_wifi_set_essid();

		netconfig_wifi_indicator_start();
	} else if (old_state == NETCONFIG_WIFI_CONNECTED) {
		vconf_set_int (VCONFKEY_WIFI_STATE, VCONFKEY_WIFI_UNCONNECTED);
		vconf_set_int(VCONFKEY_NETWORK_WIFI_STATE, VCONFKEY_NETWORK_WIFI_NOT_CONNECTED);

		__netconfig_wifi_unset_essid();

		netconfig_wifi_indicator_stop();
	}

	__netconfig_wifi_state_changed(new_state);
}

enum netconfig_wifi_service_state
netconfig_wifi_state_get_service_state(void)
{
	return wifi_service_state;
}

enum netconfig_wifi_tech_state netconfig_wifi_get_technology_state(void)
{
	DBusMessage *message = NULL;
	DBusMessageIter iter, array;
	enum netconfig_wifi_tech_state ret = NETCONFIG_WIFI_TECH_OFF;
	gboolean wifi_tech_powered = FALSE;
	gboolean wifi_tech_connected = FALSE;

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

	if (wifi_tech_powered)
		ret = NETCONFIG_WIFI_TECH_POWERED;

	if (wifi_tech_connected)
		ret = NETCONFIG_WIFI_TECH_CONNECTED;

	return ret;
}

void netconfig_wifi_update_power_state(gboolean powered)
{
	int wifi_state = 0;

	/* It's automatically updated by signal-handler
	 * DO NOT update manually
	 * It includes Wi-Fi state configuration
	 */
	vconf_get_int(VCONFKEY_WIFI_STATE, &wifi_state);

	if (powered == TRUE) {
		if (wifi_state == VCONFKEY_WIFI_OFF &&
				netconfig_is_wifi_direct_on() != TRUE &&
				netconfig_is_wifi_tethering_on() != TRUE) {
			DBG("Wi-Fi successfully turned on or waken up from power-save mode");

			vconf_set_int(VCONFKEY_NETWORK_WIFI_STATE, VCONFKEY_NETWORK_WIFI_NOT_CONNECTED);
			vconf_set_int(VCONF_WIFI_LAST_POWER_STATE, WIFI_POWER_ON);
			vconf_set_int(VCONFKEY_WIFI_STATE, VCONFKEY_WIFI_UNCONNECTED);

			netconfig_wifi_notify_power_completed(TRUE);

			netconfig_wifi_device_picker_service_start();

			netconfig_wifi_bgscan_start();
		}
	} else {
		if (wifi_state != VCONFKEY_WIFI_OFF) {
			DBG("Wi-Fi successfully turned off or in power-save mode");

			netconfig_wifi_device_picker_service_stop();

			netconfig_wifi_remove_driver();

			vconf_set_int(VCONFKEY_NETWORK_WIFI_STATE, VCONFKEY_NETWORK_WIFI_OFF);
			vconf_set_int(VCONF_WIFI_LAST_POWER_STATE, WIFI_POWER_OFF);
			vconf_set_int(VCONFKEY_WIFI_STATE, VCONFKEY_WIFI_OFF);

			netconfig_wifi_notify_power_completed(FALSE);

			netconfig_del_wifi_found_notification();

			netconfig_wifi_bgscan_stop();

			__netconfig_wifi_set_profiles_count(0);
		}
	}
}

char *netconfig_wifi_get_favorite_service(void)
{
	return __netconfig_wifi_get_connman_favorite_service();
}

void netconfig_wifi_check_network_notification(DBusMessage *message)
{
	DBusMessageIter iter;
	int profiles_count = 0;
	int qs_enable, ug_state;

	if (netconfig_wifi_state_get_service_state() == NETCONFIG_WIFI_CONNECTED) {
		DBG("Service state is connected");
		return;
	}

	if (vconf_get_int(VCONFKEY_WIFI_ENABLE_QS, &qs_enable) == -1) {
		DBG("Fail to get %s", VCONFKEY_WIFI_ENABLE_QS);
		return;
	}

	if (qs_enable != VCONFKEY_WIFI_QS_ENABLE) {
		DBG("qs_enable != VCONFKEY_WIFI_QS_ENABLE");
		return;
	}

	if (vconf_get_int(VCONFKEY_WIFI_UG_RUN_STATE, &ug_state) == -1) {
		DBG("Fail to get %s", VCONFKEY_WIFI_UG_RUN_STATE);
		return;
	}

	if (ug_state == VCONFKEY_WIFI_UG_RUN_STATE_ON_FOREGROUND) {
		DBG("ug_state == VCONFKEY_WIFI_UG_RUN_STATE_ON_FOREGROUND");
		return;
	}

	if (message == NULL) {
		ERR("Failed to get service list");
		return;
	}

	dbus_message_iter_init(message, &iter);
	DBusMessageIter array, value;
	dbus_message_iter_recurse(&iter, &array);
	if (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_STRUCT) {
		DBG("Array not found. type %d", dbus_message_iter_get_arg_type(&array));
		return;
	}

	dbus_message_iter_recurse(&array, &value);
	while (dbus_message_iter_get_arg_type(&value) == DBUS_TYPE_OBJECT_PATH) {
		const char *object_path = NULL;

		dbus_message_iter_get_basic(&value, &object_path);

		DBG("found a profile: %s", object_path);
		if (netconfig_is_wifi_profile(object_path) == TRUE) {
			profiles_count++;
			DBG("Total wifi profile cnt = %d", profiles_count);
		}

		dbus_message_iter_next(&array);
		if (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_STRUCT) {
			DBG("Not a structure entry. Arg type = %d", dbus_message_iter_get_arg_type(&array));
			break;
		}
		dbus_message_iter_recurse(&array, &value);
	}

	if (__netconfig_wifi_get_profiles_count() != profiles_count) {
		DBG("profiles prev_count (%d) - profiles count (%d)",
				__netconfig_wifi_get_profiles_count(), profiles_count);

		netconfig_add_wifi_found_notification();
		__netconfig_wifi_set_profiles_count(profiles_count);
	} else
		DBG("No change in profile count[%d]", profiles_count);
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
