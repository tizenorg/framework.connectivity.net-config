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

#include <errno.h>
#include <vconf.h>

#include "log.h"
#include "util.h"
#include "netdbus.h"
#include "neterror.h"
#include "wifi-wps.h"
#include "wifi-power.h"
#include "wifi-state.h"
#include "netsupplicant.h"
#include "wifi-background-scan.h"

#define NETCONFIG_SSID_LEN						32
#define NETCONFIG_BSSID_LEN						6
#define NETCONFIG_WPS_DBUS_REPLY_TIMEOUT		(10 * 1000)

#define VCONF_WIFI_ALWAYS_ALLOW_SCANNING \
	"file/private/wifi/always_allow_scanning"

static gboolean netconfig_is_wps_enabled = FALSE;
static gboolean netconfig_is_device_scanning = FALSE;
static gboolean netconfig_is_wps_scan_aborted = FALSE;
static int wps_bss_list_count = 0;

struct wps_bss_info_t {
	unsigned char ssid[NETCONFIG_SSID_LEN + 1];
	unsigned char bssid[NETCONFIG_BSSID_LEN + 1];
	int ssid_len;
	int rssi;
	int mode;
};

static GSList *wps_bss_info_list = NULL;

static void __netconfig_wps_set_mode(gboolean enable)
{
	if (netconfig_is_wps_enabled == enable)
		return;

	netconfig_is_wps_enabled = enable;
}

gboolean netconfig_wifi_is_wps_enabled(void)
{
	return netconfig_is_wps_enabled;
}

static void __netconfig_wifi_wps_notify_scan_done(void)
{
	DBusMessage *signal;
	DBusConnection *connection = NULL;
	DBusMessageIter dict, type, array, value, iter;
	DBusError error;

	GSList* list = NULL;
	const char *prop_ssid = "ssid";
	const char *prop_bssid = "bssid";
	const char *prop_rssi = "rssi";
	const char *prop_mode = "mode";
	const char *sig_name = "WpsScanCompleted";

	dbus_error_init(&error);

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
	if (connection == NULL) {
		ERR("Failed to get system DBus, error [%s]", error.message);
		dbus_error_free(&error);
		return;
	}

	signal = dbus_message_new_signal(NETCONFIG_WIFI_PATH,
						NETCONFIG_WIFI_INTERFACE, sig_name);
	if (signal == NULL) {
		dbus_connection_unref(connection);
		return;
	}

	dbus_message_iter_init_append(signal, &array);
	dbus_message_iter_open_container(&array, DBUS_TYPE_ARRAY, "{sv}", &dict);

	for (list = wps_bss_info_list; list != NULL; list = list->next) {
		struct wps_bss_info_t *bss_info = (struct wps_bss_info_t *)list->data;

		if (bss_info) {
			char bssid_buff[18] = { 0, };
			char *bssid_str = bssid_buff;
			unsigned char *ssid = (unsigned char *)bss_info->ssid;
			int ssid_len = (int)bss_info->ssid_len;
			int rssi = (int)bss_info->rssi;
			int mode = (int)bss_info->mode;
			g_snprintf(bssid_buff, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
					bss_info->bssid[0], bss_info->bssid[1], bss_info->bssid[2],
					bss_info->bssid[3], bss_info->bssid[4], bss_info->bssid[5]);

			DBG("BSS found; SSID %s, BSSID %s, RSSI %d MODE %d", ssid, bssid_str, rssi, mode);

			dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, 0, &type);
			dbus_message_iter_append_basic(&type, DBUS_TYPE_STRING, &prop_ssid);
			dbus_message_iter_open_container(&type, DBUS_TYPE_VARIANT,
					DBUS_TYPE_ARRAY_AS_STRING
					DBUS_TYPE_BYTE_AS_STRING,
					&value);
			dbus_message_iter_open_container(&value, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE_AS_STRING, &iter);
			dbus_message_iter_append_fixed_array(&iter, DBUS_TYPE_BYTE, &ssid, ssid_len);
			dbus_message_iter_close_container(&value, &iter);
			dbus_message_iter_close_container(&type, &value);
			dbus_message_iter_close_container(&dict, &type);

			dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, 0, &type);
			dbus_message_iter_append_basic(&type, DBUS_TYPE_STRING, &prop_bssid);
			dbus_message_iter_open_container(&type, DBUS_TYPE_VARIANT, DBUS_TYPE_STRING_AS_STRING, &value);
			dbus_message_iter_append_basic(&value, DBUS_TYPE_STRING, &bssid_str);
			dbus_message_iter_close_container(&type, &value);
			dbus_message_iter_close_container(&dict, &type);

			dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, 0, &type);
			dbus_message_iter_append_basic(&type, DBUS_TYPE_STRING, &prop_rssi);
			dbus_message_iter_open_container(&type, DBUS_TYPE_VARIANT, DBUS_TYPE_INT32_AS_STRING, &value);
			dbus_message_iter_append_basic(&value, DBUS_TYPE_INT32, &rssi);
			dbus_message_iter_close_container(&type, &value);
			dbus_message_iter_close_container(&dict, &type);

			dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, 0, &type);
			dbus_message_iter_append_basic(&type, DBUS_TYPE_STRING, &prop_mode);
			dbus_message_iter_open_container(&type, DBUS_TYPE_VARIANT, DBUS_TYPE_INT32_AS_STRING, &value);
			dbus_message_iter_append_basic(&value, DBUS_TYPE_INT32, &mode);
			dbus_message_iter_close_container(&type, &value);
			dbus_message_iter_close_container(&dict, &type);
		}
	}

	dbus_message_iter_close_container(&array, &dict);

	dbus_connection_send(connection, signal, NULL);

	dbus_message_unref(signal);
	dbus_connection_unref(connection);

	g_slist_free_full(wps_bss_info_list, g_free);
	wps_bss_info_list = NULL;
	wps_bss_list_count = 0;
}

static void __netconfig_wifi_wps_get_bss_info_result(
		DBusPendingCall *call, void *data)
{
	DBusMessage *reply;
	DBusMessageIter iter;
	DBusMessageIter dict;
	struct wps_bss_info_t *bss_info;

	reply = dbus_pending_call_steal_reply(call);

	if (dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_ERROR)
		goto done;

	if (dbus_message_iter_init(reply, &iter) == FALSE)
		goto done;

	bss_info = g_try_new0(struct wps_bss_info_t, 1);
	if (bss_info == NULL)
		goto done;

	if (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_ARRAY) {
		dbus_message_iter_recurse(&iter, &dict);

		while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
			DBusMessageIter entry, value;
			const char *key;

			dbus_message_iter_recurse(&dict, &entry);

			if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
				break;

			dbus_message_iter_get_basic(&entry, &key);
			dbus_message_iter_next(&entry);

			if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_VARIANT)
				break;

			dbus_message_iter_recurse(&entry, &value);

			if (key != NULL) {
				if (g_strcmp0(key, "BSSID") == 0) {
					DBusMessageIter array;
					unsigned char *bssid;
					int bssid_len;

					dbus_message_iter_recurse(&value, &array);
					dbus_message_iter_get_fixed_array(&array, &bssid, &bssid_len);

					if (bssid_len == NETCONFIG_BSSID_LEN)
						memcpy(bss_info->bssid, bssid, bssid_len);
				} else if (g_strcmp0(key, "SSID") == 0) {
					DBusMessageIter array;
					unsigned char *ssid;
					int ssid_len;

					dbus_message_iter_recurse(&value, &array);
					dbus_message_iter_get_fixed_array(&array, &ssid, &ssid_len);

					if (ssid_len > 0 && ssid_len <= NETCONFIG_SSID_LEN) {
						memcpy(bss_info->ssid, ssid, ssid_len);
						bss_info->ssid_len = ssid_len;
					} else {
						memset(bss_info->ssid, 0, sizeof(bss_info->ssid));
						bss_info->ssid_len = 0;
					}
				} else if (g_strcmp0(key, "Mode") == 0) {;
					const char *mode = NULL;

					dbus_message_iter_get_basic(&value, &mode);

					if (mode == NULL)
						bss_info->mode = 0;
					else {
						if (g_str_equal(mode, "infrastructure") == TRUE)
							bss_info->mode = 1;
						else if (g_str_equal(mode, "ad-hoc") == TRUE)
							bss_info->mode = 2;
						else
							bss_info->mode = 0;
					}
				} else if (g_strcmp0(key, "Signal") == 0) {
					dbus_int16_t signal = 0;

					dbus_message_iter_get_basic(&value, &signal);

					bss_info->rssi = signal;
				}
			}

			dbus_message_iter_next(&dict);
		}
	}

	if (bss_info->ssid[0] == '\0')
		g_free(bss_info);
	else
		wps_bss_info_list = g_slist_append(wps_bss_info_list, bss_info);

done:
	dbus_message_unref(reply);

	dbus_pending_call_unref(call);

	wps_bss_list_count--;
	if (wps_bss_list_count <= 0) {
		__netconfig_wifi_wps_notify_scan_done();

		if (netconfig_is_wps_scan_aborted == FALSE)
			netconfig_wifi_driver_and_supplicant(FALSE);
	}
}

static void __netconfig_wifi_wps_get_bss_info(const char *path, int index)
{
	gboolean reply = FALSE;
	char *param0 = NULL;
	char *param_array[] = { NULL, NULL };

	param0 = g_strdup_printf("string:%s", SUPPLICANT_IFACE_BSS);
	param_array[0] = param0;
	reply = netconfig_invoke_dbus_method_nonblock(SUPPLICANT_SERVICE,
			path, DBUS_INTERFACE_PROPERTIES,
			"GetAll", param_array, __netconfig_wifi_wps_get_bss_info_result);
	if (reply != TRUE)
		ERR("Fail to invoke_dbus_method_nonblock GetAll");

	if (param0)
		g_free(param0);
}

static void __netconfig_wifi_wps_get_bsss_result(
		DBusPendingCall *call, void *data)
{
	DBusMessage *reply;
	DBusMessageIter iter;
	char *path;
	gboolean counter_flag = FALSE;

	reply = dbus_pending_call_steal_reply(call);

	if (dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_ERROR)
		goto done;

	if (dbus_message_iter_init(reply, &iter) == FALSE)
		goto done;

	if (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_VARIANT) {
		DBusMessageIter variant, entry;

		dbus_message_iter_recurse(&iter, &variant);

		if (dbus_message_iter_get_arg_type(&variant) == DBUS_TYPE_ARRAY) {
			dbus_message_iter_recurse(&variant, &entry);
			while (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_INVALID) {
				dbus_message_iter_get_basic(&entry, &path);
				if (path != NULL && g_strcmp0(path, "/") != 0) {
					__netconfig_wifi_wps_get_bss_info(path, ++wps_bss_list_count);

					counter_flag = TRUE;
				}

				dbus_message_iter_next(&entry);
			}
		}
	}

done:
	dbus_message_unref(reply);

	dbus_pending_call_unref(call);

	/* Send WpsScanCompleted signal even when the BSS count is 0 */
	if (wps_bss_list_count <= 0 && counter_flag == FALSE) {
		__netconfig_wifi_wps_notify_scan_done();

		if (netconfig_is_wps_scan_aborted == FALSE)
			netconfig_wifi_driver_and_supplicant(FALSE);
	}
}

static int _netconfig_wifi_wps_get_bsss(void)
{
	gboolean reply = FALSE;
	const char *if_path = NULL;
	char *param0 = NULL;
	char param1[] = "string:BSSs";
	char *param_array[] = { NULL, NULL, NULL };

	if_path = netconfig_wifi_get_supplicant_interface();
	if (if_path == NULL) {
		DBG("Fail to get wpa_supplicant DBus path");
		return -ESRCH;
	}

	param0 = g_strdup_printf("string:%s", SUPPLICANT_IFACE_INTERFACE);
	param_array[0] = param0;
	param_array[1] = param1;

	reply = netconfig_invoke_dbus_method_nonblock(SUPPLICANT_SERVICE,
			if_path, DBUS_INTERFACE_PROPERTIES,
			"Get", param_array, __netconfig_wifi_wps_get_bsss_result);
	if (reply != TRUE) {
		ERR("Fail to invoke_dbus_method_nonblock Get");

		if (param0)
			g_free(param0);
		return -ESRCH;
	}

	if (param0)
		g_free(param0);
	return 0;
}

void netconfig_wifi_wps_signal_scandone(void)
{
	wps_bss_list_count = 0;
	_netconfig_wifi_wps_get_bsss();

	netconfig_is_device_scanning = FALSE;

	__netconfig_wps_set_mode(FALSE);
}

void netconfig_wifi_wps_signal_scanaborted(void)
{
	wps_bss_list_count = 0;
	netconfig_is_wps_scan_aborted = TRUE;
	_netconfig_wifi_wps_get_bsss();

	netconfig_is_device_scanning = FALSE;

	__netconfig_wps_set_mode(FALSE);
}

static int __netconfig_wifi_wps_request_scan(const char *if_path)
{
	dbus_bool_t result = FALSE;
	DBusConnection *connection = NULL;
	DBusMessage *message = NULL;
	DBusPendingCall *call;
	DBusMessageIter iter, dict, entry;
	DBusMessageIter value;
	const char *key1 = "Type";
	const char *val1 = "passive";

	if (if_path == NULL)
		if_path = netconfig_wifi_get_supplicant_interface();

	if (if_path == NULL) {
		DBG("Fail to get wpa_supplicant DBus path");
		return -ESRCH;
	}

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (connection == NULL) {
		ERR("Failed to get system bus");
		return -EIO;
	}

	message = dbus_message_new_method_call(SUPPLICANT_SERVICE,
					if_path, SUPPLICANT_INTERFACE ".Interface", "Scan");
	if (message == NULL) {
		ERR("Failed DBus method call");
		dbus_connection_unref(connection);
		return -EIO;
	}

	dbus_message_iter_init_append(message, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);

	dbus_message_iter_open_container(&dict,
			DBUS_TYPE_DICT_ENTRY, NULL, &entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key1);

	dbus_message_iter_open_container(&entry,
			DBUS_TYPE_VARIANT, DBUS_TYPE_STRING_AS_STRING, &value);
	dbus_message_iter_append_basic(&value, DBUS_TYPE_STRING, &val1);

	dbus_message_iter_close_container(&entry, &value);
	dbus_message_iter_close_container(&dict, &entry);
	dbus_message_iter_close_container(&iter, &dict);

	result = dbus_connection_send_with_reply(connection, message, &call,
			NETCONFIG_WPS_DBUS_REPLY_TIMEOUT);
	if (result == FALSE || call == NULL) {
		ERR("dbus_connection_send_with_reply() failed");

		dbus_message_unref(message);
		dbus_connection_unref(connection);

		return -ESRCH;
	}

	dbus_pending_call_cancel(call);
	dbus_message_unref(message);
	dbus_connection_unref(connection);

	/* Clear bss_info_list for the next scan result */
	if (wps_bss_info_list) {
		g_slist_free_full(wps_bss_info_list, g_free);
		wps_bss_info_list = NULL;
	}

	netconfig_is_wps_scan_aborted = FALSE;

	return 0;
}

static void __netconfig_wifi_interface_create_result(
		DBusPendingCall *call, void *data)
{
	DBusMessage *message;
	DBusMessageIter iter;
	const char *path = NULL;

	message = dbus_pending_call_steal_reply(call);
	if (dbus_message_get_type(message) != DBUS_MESSAGE_TYPE_ERROR) {
		dbus_message_iter_init(message, &iter);
		dbus_message_iter_get_basic(&iter, &path);

		if (path)
			__netconfig_wifi_wps_request_scan(path);
	} else {
		DBG("Failed to create interface");
	}

	dbus_message_unref(message);
	dbus_pending_call_unref(call);
}

static int  __netconfig_wifi_wps_create_interface(void)
{
	dbus_bool_t result = FALSE;
	DBusConnection *connection = NULL;
	DBusMessage *message = NULL;
	DBusPendingCall *call;
	DBusMessageIter iter, dict, entry, value;
	const char *key = "Ifname";
	const char *val = WIFI_IFNAME;

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (connection == NULL) {
		ERR("Failed to get system bus");
		return -EIO;
	}

	message = dbus_message_new_method_call(SUPPLICANT_SERVICE,
				SUPPLICANT_PATH, SUPPLICANT_INTERFACE, "CreateInterface");
	if (message == NULL) {
		ERR("Failed DBus method call");
		dbus_connection_unref(connection);
		return -EIO;
	}

	dbus_message_iter_init_append(message, &iter);
	dbus_message_iter_open_container(&iter, DBUS_TYPE_ARRAY,
			DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
			DBUS_TYPE_STRING_AS_STRING DBUS_TYPE_VARIANT_AS_STRING
			DBUS_DICT_ENTRY_END_CHAR_AS_STRING, &dict);
	dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY,
			NULL, &entry);

	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key);
	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
			DBUS_TYPE_STRING_AS_STRING, &value);
	dbus_message_iter_append_basic(&value, DBUS_TYPE_STRING, &val);
	dbus_message_iter_close_container(&entry, &value);
	dbus_message_iter_close_container(&dict, &entry);
	dbus_message_iter_close_container(&iter, &dict);

	result = dbus_connection_send_with_reply(connection, message, &call,
				NETCONFIG_WPS_DBUS_REPLY_TIMEOUT);
	if (result == FALSE || call == NULL) {
		ERR("dbus_connection_send_with_reply() failed");

		dbus_message_unref(message);
		dbus_connection_unref(connection);

		return -ESRCH;
	}

	dbus_pending_call_set_notify(call,
			__netconfig_wifi_interface_create_result, NULL, NULL);

	dbus_message_unref(message);
	dbus_connection_unref(connection);

	return 0;
}

static int __netconfig_wifi_wps_scan(void)
{
	int err = 0;
	enum netconfig_wifi_tech_state wifi_tech_state;

	if (netconfig_is_device_scanning == TRUE)
		return -EINPROGRESS;

	wifi_tech_state = netconfig_wifi_state_get_technology_state();
	if (wifi_tech_state <= NETCONFIG_WIFI_TECH_OFF)
		err = netconfig_wifi_driver_and_supplicant(TRUE);

	if (err < 0 && err != -EALREADY)
		return err;

	netconfig_is_device_scanning = TRUE;

	DBG("WPS scan requested");
	if (wifi_tech_state >= NETCONFIG_WIFI_TECH_POWERED) {
		if (netconfig_wifi_get_scanning() == TRUE)
			return -EINPROGRESS;

		netconfig_wifi_bgscan_start(TRUE);

		if (wifi_tech_state == NETCONFIG_WIFI_TECH_CONNECTED)
			__netconfig_wifi_wps_request_scan(NULL);
	} else {
		err = __netconfig_wifi_wps_create_interface();
	}

	return err;
}

gboolean netconfig_iface_wifi_request_wps_scan(NetconfigWifi *wifi,
		GError **error)
{
	int err, enabled = 0;
	enum netconfig_wifi_tech_state wifi_tech_state;

	g_return_val_if_fail(wifi != NULL, FALSE);

	if (netconfig_is_wifi_tethering_on() == TRUE) {
		ERR("Wi-Fi Tethering is enabled");
		return -EBUSY;
	}

#if !defined TIZEN_WEARABLE
	if (netconfig_wifi_is_bgscan_paused()) {
		ERR("Scan is paused");
		return FALSE;
	}
#endif

	wifi_tech_state = netconfig_wifi_state_get_technology_state();
	if (wifi_tech_state <= NETCONFIG_WIFI_TECH_OFF) {
		vconf_get_int(VCONF_WIFI_ALWAYS_ALLOW_SCANNING, &enabled);

		if (enabled == 0) {
			netconfig_error_permission_denied(error);
			return FALSE;
		}
	}

	__netconfig_wps_set_mode(TRUE);

	err = __netconfig_wifi_wps_scan();
	if (err < 0) {
		if (err == -EINPROGRESS)
			netconfig_error_inprogress(error);
		else
			netconfig_error_wifi_driver_failed(error);

		return FALSE;
	}

	return TRUE;
}
