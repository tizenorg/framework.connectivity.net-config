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
#include <bundle.h>
#include <bundle_internal.h>
#include <eventsystem.h>

#include "log.h"
#include "util.h"
#include "netdbus.h"
#include "wifi-state.h"
#include "wifi-power.h"
#include "netsupplicant.h"
#include "network-state.h"
#include "wifi-indicator.h"
#include "network-statistics.h"
#include "wifi-background-scan.h"

#define NETCONFIG_NETWORK_NOTIFICATION_TIMEOUT	15 * 1000

static gboolean new_bss_found = FALSE;
static guint network_noti_timer_id = 0;

static wifi_service_state_e g_service_state = NETCONFIG_WIFI_UNKNOWN;
static wifi_tech_state_e g_tech_state = NETCONFIG_WIFI_TECH_UNKNOWN;

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

static void __set_wifi_connected_essid(void)
{
	const char *essid_name = NULL;
	const char *wifi_profile = netconfig_get_default_profile();

	if (wifi_state_get_service_state() != NETCONFIG_WIFI_CONNECTED)
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

static void __unset_wifi_connected_essid(void)
{
	netconfig_set_vconf_str(VCONFKEY_WIFI_CONNECTED_AP_NAME, "");
}

static const char *__get_wifi_connected_essid(void)
{
	const char *essid_name = NULL;
	const char *wifi_profile = NULL;

	if (wifi_state_get_service_state() != NETCONFIG_WIFI_CONNECTED)
		return NULL;

	wifi_profile = netconfig_get_default_profile();

	if (wifi_profile == NULL || netconfig_is_wifi_profile(wifi_profile) != TRUE) {
		ERR("Can't get Wi-Fi profile");
		return NULL;
	}

	essid_name = netconfig_wifi_get_connected_essid(wifi_profile);
	if (essid_name == NULL) {
		ERR("Can't get Wi-Fi name");
		return NULL;
	}

	return essid_name;
}

static gboolean __is_wifi_profile_available(void)
{
	GVariant *message = NULL;
	GVariantIter *iter, *next;
	gchar *obj;

	message = netconfig_invoke_dbus_method(CONNMAN_SERVICE,
			CONNMAN_MANAGER_PATH, CONNMAN_MANAGER_INTERFACE,
			"GetServices", NULL);
	if (message == NULL) {
		ERR("Failed to get service list");
		return FALSE;
	}

	g_variant_get(message, "(a(oa{sv}))", &iter);
	while (g_variant_iter_loop(iter, "(oa{sv})", &obj, &next)) {
		if (obj == NULL || netconfig_is_wifi_profile((const gchar*)obj) == FALSE) {
			continue;
		}

		g_variant_iter_free(next);
		g_free(obj);
		break;
	}

	g_variant_unref(message);

	g_variant_iter_free(iter);

	return TRUE;
}

static gboolean __is_favorited(GVariantIter *array)
{
	gboolean is_favorite = FALSE;
	gchar *key;
	GVariant *var;

	while (g_variant_iter_loop(array, "{sv}", &key, &var)) {
		gboolean value;

		if (g_str_equal(key, "Favorite") != TRUE) {
			continue;
		}

		value = g_variant_get_boolean(var);
		if (value)
			is_favorite = TRUE;
		g_free(key);
		g_variant_unref(var);
		break;
	}

	return is_favorite;
}

static void _wifi_state_connected_activation(void)
{
	/* Add activation of services when Wi-Fi is connected */
	bundle *b = NULL;

	b = bundle_create();
	aul_launch_app("com.samsung.keepit-service-standby", b);
	bundle_free(b);
}

static void _wifi_state_changed(wifi_service_state_e state)
{
	GSList *list;

	for (list = notifier_list; list; list = list->next) {
		wifi_state_notifier *notifier = list->data;

		if (notifier->wifi_state_changed != NULL)
			notifier->wifi_state_changed(state, notifier->user_data);
	}
}

static void _set_bss_found(gboolean found)
{
	if (found != new_bss_found)
		new_bss_found = found;
}

static gboolean _check_network_notification(gpointer data)
{
	int qs_enable = 0, ug_state = 0;
	static gboolean check_again = FALSE;

	wifi_tech_state_e tech_state;
	wifi_service_state_e service_state;

	tech_state = wifi_state_get_technology_state();
	if (tech_state < NETCONFIG_WIFI_TECH_POWERED) {
		DBG("Wi-Fi off or WPS only supported[%d]", tech_state);
		goto cleanup;
	}

	service_state = wifi_state_get_service_state();
	if (service_state == NETCONFIG_WIFI_CONNECTED) {
		DBG("Service state is connected");
		goto cleanup;
	} else if (service_state == NETCONFIG_WIFI_ASSOCIATION ||
		service_state == NETCONFIG_WIFI_CONFIGURATION) {
		DBG("Service state is connecting (check again : %d)", check_again);
		if (!check_again) {
			check_again = TRUE;
			return TRUE;
		} else
			check_again = FALSE;
	}

	if (__is_wifi_profile_available() == FALSE) {
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

	_set_bss_found(FALSE);

cleanup:
	netconfig_stop_timer(&network_noti_timer_id);
	return FALSE;
}

static char *_get_connman_favorite_service(void)
{
	char *favorite_service = NULL;
	GVariant *message = NULL;
	gchar *obj;
	GVariantIter *iter, *next;

	message = netconfig_invoke_dbus_method(CONNMAN_SERVICE,
			CONNMAN_MANAGER_PATH, CONNMAN_MANAGER_INTERFACE,
			"GetServices", NULL);
	if (message == NULL) {
		ERR("Failed to get service list");
		return NULL;
	}

	g_variant_get(message, "(a(oa{sv}))", &iter);
	while (g_variant_iter_loop(iter, "(oa{sv})", &obj, &next)) {
		if (obj == NULL || netconfig_is_wifi_profile(obj) == FALSE) {
			continue;
		}

		if (__is_favorited(next) == TRUE) {
			favorite_service = g_strdup(obj);
			g_free(obj);
			g_variant_iter_free(next);
			break;
		}
	}

	g_variant_iter_free(iter);
	g_variant_unref(message);

	return favorite_service;
}

static void __notification_value_changed_cb(keynode_t *node, void *user_data)
{
	int value = -1;

	if (vconf_get_int(VCONFKEY_WIFI_ENABLE_QS, &value) < 0) {
		return;
	}

	if (value == VCONFKEY_WIFI_QS_DISABLE) {
		netconfig_send_notification_to_net_popup(NETCONFIG_DEL_FOUND_AP_NOTI, NULL);
	}
}

static void _register_network_notification(void)
{
#if defined TIZEN_WEARABLE
	return;
#endif
	vconf_notify_key_changed(VCONFKEY_WIFI_ENABLE_QS, __notification_value_changed_cb, NULL);
}

static void _deregister_network_notification(void)
{
#if defined TIZEN_WEARABLE
		return;
#endif
	vconf_ignore_key_changed(VCONFKEY_WIFI_ENABLE_QS, __notification_value_changed_cb);
}

static void _set_power_save(gboolean power_save)
{
	gboolean result;
	const char *if_path;
	GVariant *input_args = NULL;
	static gboolean old_state = TRUE;
	const gchar *args_disable = "POWERMODE 1";
	const gchar *args_enable = "POWERMODE 0";
	if (old_state == power_save)
		return;

	if_path = netconfig_wifi_get_supplicant_interface();
	if (if_path == NULL) {
		ERR("Fail to get wpa_supplicant DBus path");
		return;
	}

	if (power_save)
		input_args = g_variant_new_string(args_enable);
	else
		input_args = g_variant_new_string(args_disable);

	result = netconfig_supplicant_invoke_dbus_method_nonblock(
			SUPPLICANT_SERVICE,
			if_path,
			SUPPLICANT_INTERFACE ".Interface",
			"Driver",
			input_args,
			NULL);
	if (result == FALSE)
		ERR("Fail to set power save mode POWERMODE %d", power_save);
	else
		old_state = power_save;

	return;
}

static void _set_power_lock(gboolean power_lock)
{
	gint32 ret = 0;
	GVariant *reply;
	GVariant *params;
	char state[] = "lcdoff";
	char flag[] = "staycurstate";
	char standby[] = "NULL";
	int timeout = 0;
	char sleepmargin[] = "sleepmargin";

	const char *lockstate = "lockstate";
	const char *unlockstate = "unlockstate";
	static gboolean old_state = FALSE;
	const char *lock_method;

	if (old_state == power_lock)
		return;

	if (power_lock == TRUE) {
		/* deviced power lock enable */
		params = g_variant_new("(sssi)", state, flag, standby, timeout);

		lock_method = lockstate;
	} else {
		/* deviced power lock disable */
		params = g_variant_new("(ss)", state, sleepmargin);

		lock_method = unlockstate;
	}

	reply = netconfig_invoke_dbus_method(
			"org.tizen.system.deviced",
			"/Org/Tizen/System/DeviceD/Display",
			"org.tizen.system.deviced.display",
			lock_method,
			params);
	if (reply == NULL){
		ERR("Failed to set_power_lock");
		return;
	}

	ret = g_variant_get_int32(reply);
	if (ret < 0)
		ERR("Failed to set power lock %s with ret %d",
				power_lock == TRUE ? "enable" : "disable", ret);
	else
		old_state = power_lock;

	g_variant_unref(reply);

	return;
}

void wifi_state_emit_power_completed(gboolean power_on)
{
	if (power_on)
		wifi_emit_power_on_completed((Wifi *)get_wifi_object());
	else
		wifi_emit_power_off_completed((Wifi *)get_wifi_object());

	DBG("Successfully sent signal [%s]",(power_on)?"powerOn":"powerOff");
}

void wifi_state_emit_power_failed(void)
{
	wifi_emit_power_operation_failed((Wifi *)get_wifi_object());

	DBG("Successfully sent signal [PowerOperationFailed]");
}

void wifi_state_update_power_state(gboolean powered)
{
	wifi_tech_state_e tech_state;

	/* It's automatically updated by signal-handler
	 * DO NOT update manually
	 * It includes Wi-Fi state configuration
	 */
	tech_state = wifi_state_get_technology_state();

	if (powered == TRUE) {
		if (tech_state < NETCONFIG_WIFI_TECH_POWERED && netconfig_is_wifi_tethering_on() != TRUE) {
			DBG("Wi-Fi turned on or waken up from power-save mode");

			wifi_state_set_tech_state(NETCONFIG_WIFI_TECH_POWERED);

			wifi_state_emit_power_completed(TRUE);

			netconfig_wifi_device_picker_service_start();

			netconfig_set_vconf_int(VCONF_WIFI_LAST_POWER_STATE, VCONFKEY_WIFI_UNCONNECTED);
			netconfig_set_vconf_int(VCONFKEY_WIFI_STATE, VCONFKEY_WIFI_UNCONNECTED);
			netconfig_set_vconf_int(VCONFKEY_NETWORK_WIFI_STATE, VCONFKEY_NETWORK_WIFI_NOT_CONNECTED);

			netconfig_set_system_event(SYS_EVENT_WIFI_STATE, EVT_KEY_WIFI_STATE, EVT_VAL_WIFI_ON);

			netconfig_wifi_bgscan_stop();
			netconfig_wifi_bgscan_start(TRUE);

			/* Add callback to track change in notification setting */
			_register_network_notification();
		}
	} else if (tech_state > NETCONFIG_WIFI_TECH_OFF) {
		DBG("Wi-Fi turned off or in power-save mode");

		wifi_state_set_tech_state(NETCONFIG_WIFI_TECH_WPS_ONLY);

		netconfig_wifi_device_picker_service_stop();

		wifi_power_disable_technology_state_by_only_connman_signal();
		wifi_power_driver_and_supplicant(FALSE);

		wifi_state_emit_power_completed(FALSE);

		netconfig_set_vconf_int(VCONF_WIFI_LAST_POWER_STATE, VCONFKEY_WIFI_OFF);
		netconfig_set_vconf_int(VCONFKEY_WIFI_STATE, VCONFKEY_WIFI_OFF);
		netconfig_set_vconf_int(VCONFKEY_NETWORK_WIFI_STATE, VCONFKEY_NETWORK_WIFI_OFF);

		netconfig_set_system_event(SYS_EVENT_WIFI_STATE, EVT_KEY_WIFI_STATE, EVT_VAL_WIFI_OFF);

		netconfig_wifi_set_bgscan_pause(FALSE);
		netconfig_wifi_bgscan_stop();

		_set_bss_found(FALSE);

		/* Inform net-popup to remove the wifi found notification */
		netconfig_send_notification_to_net_popup(NETCONFIG_DEL_FOUND_AP_NOTI, NULL);
		netconfig_send_notification_to_net_popup(NETCONFIG_DEL_PORTAL_NOTI, NULL);

		_deregister_network_notification();
	}
}

char *wifi_get_favorite_service(void)
{
	return _get_connman_favorite_service();
}

void wifi_start_timer_network_notification(void)
{
#if defined TIZEN_WEARABLE
		/* In case of wearable device, no need to notify available Wi-Fi APs */
		return ;
#endif
	netconfig_start_timer(NETCONFIG_NETWORK_NOTIFICATION_TIMEOUT, _check_network_notification, NULL, &network_noti_timer_id);
}

void wifi_state_notifier_register(wifi_state_notifier *notifier)
{
	DBG("register notifier");

	notifier_list = g_slist_append(notifier_list, notifier);
}

void wifi_state_notifier_unregister(wifi_state_notifier *notifier)
{
	DBG("un-register notifier");

	notifier_list = g_slist_remove_all(notifier_list, notifier);
}

void wifi_state_notifier_cleanup(void)
{
	g_slist_free_full(notifier_list, NULL);
}

void wifi_state_set_bss_found(gboolean found)
{
	_set_bss_found(found);
}

gboolean wifi_state_is_bss_found(void)
{
	return new_bss_found;
}

void wifi_state_set_service_state(wifi_service_state_e new_state)
{
	static gboolean dhcp_stage = FALSE;
	wifi_service_state_e old_state = g_service_state;

	if (old_state == new_state)
		return;

	g_service_state = new_state;
	DBG("Wi-Fi state %d ==> %d", old_state, new_state);

	/* During DHCP, temporarily disable Wi-Fi power saving */
	if ((old_state < NETCONFIG_WIFI_ASSOCIATION || old_state == NETCONFIG_WIFI_FAILURE) && new_state == NETCONFIG_WIFI_CONFIGURATION) {
		_set_power_lock(TRUE);
		_set_power_save(FALSE);
		dhcp_stage = TRUE;
	} else if (dhcp_stage == TRUE) {
		_set_power_lock(FALSE);
		_set_power_save(TRUE);
		dhcp_stage = FALSE;
	}

	if (new_state == NETCONFIG_WIFI_CONNECTED) {
		netconfig_send_notification_to_net_popup(NETCONFIG_DEL_FOUND_AP_NOTI, NULL);

		netconfig_set_vconf_int(VCONFKEY_WIFI_STATE, VCONFKEY_WIFI_CONNECTED);
		netconfig_set_vconf_int(VCONFKEY_NETWORK_WIFI_STATE, VCONFKEY_NETWORK_WIFI_CONNECTED);

		netconfig_set_system_event(SYS_EVENT_WIFI_STATE, EVT_KEY_WIFI_STATE, EVT_VAL_WIFI_CONNECTED);

		__set_wifi_connected_essid();

		netconfig_wifi_indicator_start();
	} else if (old_state == NETCONFIG_WIFI_CONNECTED) {
		netconfig_send_notification_to_net_popup(NETCONFIG_DEL_PORTAL_NOTI, NULL);

		__unset_wifi_connected_essid();

		netconfig_set_vconf_int (VCONFKEY_WIFI_STATE, VCONFKEY_WIFI_UNCONNECTED);
		netconfig_set_vconf_int(VCONFKEY_NETWORK_WIFI_STATE, VCONFKEY_NETWORK_WIFI_NOT_CONNECTED);

		netconfig_set_system_event(SYS_EVENT_WIFI_STATE, EVT_KEY_WIFI_STATE, EVT_VAL_WIFI_ON);

		netconfig_wifi_indicator_stop();

		netconfig_wifi_set_bgscan_pause(FALSE);

		netconfig_wifi_bgscan_stop();
		netconfig_wifi_bgscan_start(TRUE);
	} else if ((old_state > NETCONFIG_WIFI_IDLE && old_state < NETCONFIG_WIFI_CONNECTED) && new_state == NETCONFIG_WIFI_IDLE){
		//in ipv6 case disconnect/association -> association
		DBG("reset the bg scan period");
		netconfig_wifi_set_bgscan_pause(FALSE);

		netconfig_wifi_bgscan_stop();
		netconfig_wifi_bgscan_start(TRUE);
	}

	_wifi_state_changed(new_state);

	if (new_state == NETCONFIG_WIFI_CONNECTED){
		_wifi_state_connected_activation();
#if defined TIZEN_WEARABLE
		wc_launch_syspopup(WC_POPUP_TYPE_WIFI_CONNECTED);
#endif
	}
}

wifi_service_state_e wifi_state_get_service_state(void)
{
	return g_service_state;
}

void wifi_state_set_tech_state(wifi_tech_state_e new_state)
{
	wifi_tech_state_e old_state = g_tech_state;

	if (old_state == new_state)
		return;

	g_tech_state = new_state;

	DBG("Wi-Fi technology state %d ==> %d", old_state, new_state);
}

wifi_tech_state_e wifi_state_get_technology_state(void)
{
	GVariant *message = NULL, *variant;
	GVariantIter *iter, *next;
	wifi_tech_state_e ret = NETCONFIG_WIFI_TECH_OFF;
	gboolean wifi_tech_powered = FALSE;
	gboolean wifi_tech_connected = FALSE;
	const char *path;
	gchar *key;

	if (g_tech_state > NETCONFIG_WIFI_TECH_UNKNOWN)
		return g_tech_state;

	message = netconfig_invoke_dbus_method(CONNMAN_SERVICE,
			CONNMAN_MANAGER_PATH, CONNMAN_MANAGER_INTERFACE,
			"GetTechnologies", NULL);
	if (message == NULL) {
		ERR("Failed to get_technology_state");
		return NETCONFIG_WIFI_TECH_UNKNOWN;
	}

	g_variant_get(message, "(a(oa{sv}))", &iter);
	while (g_variant_iter_loop(iter, "(oa{sv})", &path, &next)) {
		if (path == NULL || g_strcmp0(path, CONNMAN_WIFI_TECHNOLOGY_PREFIX) != 0) {
			continue;
		}

		while (g_variant_iter_loop(next, "{sv}", &key, &variant)) {
			const gchar *sdata = NULL;
			gboolean data;

			if (g_variant_is_of_type(variant, G_VARIANT_TYPE_BOOLEAN)) {
				data = g_variant_get_boolean(variant);
				DBG("key-[%s] - %s", key, data ? "True" : "False");

				if (strcmp(key, "Powered") == 0 && data) {
					wifi_tech_powered = TRUE;
				} else if (strcmp(key, "Connected") == 0 && data) {
					wifi_tech_connected = TRUE;
				} else if (strcmp(key, "Tethering") == 0 && data) {
					// For further use
				}
			} else if (g_variant_is_of_type(variant, G_VARIANT_TYPE_STRING)) {
				sdata = g_variant_get_string(variant, NULL);
				DBG("%s", sdata);
			}
		}
		g_variant_iter_free (next);
	}

	g_variant_unref(message);

	g_variant_iter_free (iter);

	if (wifi_tech_powered == TRUE)
		ret = NETCONFIG_WIFI_TECH_POWERED;

	if (wifi_tech_connected == TRUE)
		ret = NETCONFIG_WIFI_TECH_CONNECTED;

	g_tech_state = ret;

	return g_tech_state;
}

void wifi_state_set_connected_essid(void)
{
	__set_wifi_connected_essid();
#if defined TIZEN_WEARABLE
	wc_launch_syspopup(WC_POPUP_TYPE_WIFI_CONNECTED);
#endif
}

void wifi_state_get_connected_essid(gchar **essid)
{
	*essid = g_strdup(__get_wifi_connected_essid());
}

/*	wifi_connection_state_e in CAPI
 *
 *	WIFI_CONNECTION_STATE_FAILURE		= -1
 *	WIFI_CONNECTION_STATE_DISCONNECTED	= 0
 *	WIFI_CONNECTION_STATE_ASSOCIATION	= 1
 *	WIFI_CONNECTION_STATE_CONFIGURATION	= 2
 *	WIFI_CONNECTION_STATE_CONNECTED		= 3
 */
gboolean handle_get_wifi_state(Wifi *wifi, GDBusMethodInvocation *context)
{
	g_return_val_if_fail(wifi != NULL, FALSE);
	wifi_service_state_e state = NETCONFIG_WIFI_UNKNOWN;
	gint wifi_state = 0;
	state = wifi_state_get_service_state();

	switch (state) {
	case NETCONFIG_WIFI_FAILURE:
		wifi_state = -1;
		break;
	case NETCONFIG_WIFI_UNKNOWN:
	case NETCONFIG_WIFI_IDLE:
		wifi_state = 0;
		break;
	case NETCONFIG_WIFI_ASSOCIATION:
		wifi_state = 1;
		break;
	case NETCONFIG_WIFI_CONFIGURATION:
		wifi_state = 2;
		break;
	case NETCONFIG_WIFI_CONNECTED:
		wifi_state = 3;
		break;
	default:
		wifi_state = 0;
	}

	g_dbus_method_invocation_return_value(context, g_variant_new("(i)", wifi_state));

	return TRUE;
}
