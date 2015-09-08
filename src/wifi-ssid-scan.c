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

#include "log.h"
#include "util.h"
#include "neterror.h"
#include "netdbus.h"
#include "netsupplicant.h"
#include "wifi-ssid-scan.h"
#include "wifi-background-scan.h"

enum netconfig_wifi_security {
	WIFI_SECURITY_UNKNOWN = 0x00,
	WIFI_SECURITY_NONE = 0x01,
	WIFI_SECURITY_WEP = 0x02,
	WIFI_SECURITY_PSK = 0x03,
	WIFI_SECURITY_IEEE8021X = 0x04,
};

struct bss_info_t {
	unsigned char ssid[33];
	enum netconfig_wifi_security security;
	dbus_bool_t privacy;
	dbus_bool_t wps;
};

static gboolean wifi_ssid_scan_state = FALSE;
static GSList *wifi_bss_info_list = NULL;
static guint netconfig_wifi_ssid_scan_timer = 0;
static char *g_ssid = NULL;

static gboolean __netconfig_wifi_ssid_scan_timeout(gpointer data)
{
	netconfig_wifi_notify_ssid_scan_done();

	return FALSE;
}

static void __netconfig_wifi_ssid_scan_started(void)
{
	INFO("Wi-Fi SSID scan started");
	wifi_ssid_scan_state = TRUE;

	netconfig_start_timer_seconds(5,
			__netconfig_wifi_ssid_scan_timeout,
			NULL,
			&netconfig_wifi_ssid_scan_timer);
}

static void __netconfig_wifi_ssid_scan_finished(void)
{
	INFO("Wi-Fi SSID scan finished");
	wifi_ssid_scan_state = FALSE;

	netconfig_stop_timer(&netconfig_wifi_ssid_scan_timer);
}

static gboolean __netconfig_wifi_invoke_ssid_scan(
		const char *object_path, const char *ssid)
{
	/* TODO: Revise following code */

#define NETCONFIG_DBUS_REPLY_TIMEOUT (10 * 1000)

	DBusConnection *connection = NULL;
	DBusMessage *message = NULL;
	DBusMessage *reply = NULL;
	DBusMessageIter iter, dict, entry;
	DBusMessageIter value, array, array2;
	DBusError error;
	const char *key1 = "Type";
	const char *val1 = "active";
	const char *key2 = "SSIDs";

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (connection == NULL) {
		ERR("Failed to get system DBus");
		goto error;
	}

	message = dbus_message_new_method_call(SUPPLICANT_SERVICE,
			object_path, SUPPLICANT_INTERFACE ".Interface", "Scan");
	if (message == NULL) {
		ERR("Error!!! DBus method call fail");
		goto error;
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

	dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, NULL, &entry);
	dbus_message_iter_append_basic(&entry, DBUS_TYPE_STRING, &key2);

	dbus_message_iter_open_container(&entry, DBUS_TYPE_VARIANT,
			DBUS_TYPE_ARRAY_AS_STRING
			DBUS_TYPE_ARRAY_AS_STRING
			DBUS_TYPE_BYTE_AS_STRING,
			&value);
	dbus_message_iter_open_container(&value, DBUS_TYPE_ARRAY,
			DBUS_TYPE_ARRAY_AS_STRING
			DBUS_TYPE_BYTE_AS_STRING,
			&array);
	dbus_message_iter_open_container(&array, DBUS_TYPE_ARRAY, DBUS_TYPE_BYTE_AS_STRING, &array2);

	dbus_message_iter_append_fixed_array(&array2, DBUS_TYPE_BYTE, &ssid, strlen(ssid));

	dbus_message_iter_close_container(&array, &array2);
	dbus_message_iter_close_container(&value, &array);
	dbus_message_iter_close_container(&entry, &value);
	dbus_message_iter_close_container(&dict, &entry);
	dbus_message_iter_close_container(&iter, &dict);

	dbus_error_init(&error);

	reply = dbus_connection_send_with_reply_and_block(connection, message,
			NETCONFIG_DBUS_REPLY_TIMEOUT, &error);

	if (reply == NULL) {
		if (dbus_error_is_set(&error) == TRUE) {
			ERR("Error!!! dbus_connection_send_with_reply_and_block() failed. "
					"DBus error [%s: %s]", error.name, error.message);

			dbus_error_free(&error);
			return FALSE;
		} else
			ERR("Error!!! Failed to get properties");

		goto error;
	}

	if (dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_ERROR) {
		const char *err_msg = dbus_message_get_error_name(reply);
		ERR("Error!!! Error message received %s", err_msg);
		goto error;
	}

	if (g_ssid != NULL) {
		g_free(g_ssid);
	}
	g_ssid = g_strdup(ssid);

	dbus_message_unref(message);
	dbus_message_unref(reply);
	dbus_connection_unref(connection);

	return TRUE;

error:
	if (message != NULL)
		dbus_message_unref(message);

	if (reply != NULL)
		dbus_message_unref(reply);

	if (connection != NULL)
		dbus_connection_unref(connection);

	return FALSE;
}

static void __netconfig_wifi_notify_ssid_scan_done(void)
{
	DBusMessage *signal;
	DBusConnection *connection = NULL;
	DBusMessageIter dict, type, array, value;
	DBusError error;

	GSList* list = NULL;
	const char *prop_ssid = "ssid";
	const char *prop_security = "security";
	const char *prop_wps = "wps";
	const char *sig_name = "SpecificScanCompleted";

	dbus_error_init(&error);

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, &error);
	if (connection == NULL) {
		ERR("Failed to get system DBus, error [%s]", error.message);
		dbus_error_free(&error);

		g_slist_free_full(wifi_bss_info_list, g_free);
		wifi_bss_info_list = NULL;

		return;
	}

	signal = dbus_message_new_signal(NETCONFIG_WIFI_PATH, NETCONFIG_WIFI_INTERFACE, sig_name);
	if (signal == NULL) {
		dbus_connection_unref(connection);

		g_slist_free_full(wifi_bss_info_list, g_free);
		wifi_bss_info_list = NULL;

		return;
	}

	dbus_message_iter_init_append(signal, &array);
	dbus_message_iter_open_container(&array, DBUS_TYPE_ARRAY, "{sv}", &dict);

	for (list = wifi_bss_info_list; list != NULL; list = list->next) {
		struct bss_info_t *bss_info = (struct bss_info_t *)list->data;

		if (bss_info && g_strcmp0((char *)bss_info->ssid, g_ssid) == 0) {
			char *ssid = (char *)bss_info->ssid;
			enum netconfig_wifi_security security = bss_info->security;
			dbus_bool_t wps = bss_info->wps;
			DBG("BSS found; SSID:%s security:%d WPS:%d", ssid, security, wps);

			/* SSID */
			dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, 0, &type);
			dbus_message_iter_append_basic(&type, DBUS_TYPE_STRING, &prop_ssid);
			dbus_message_iter_open_container(&type, DBUS_TYPE_VARIANT, DBUS_TYPE_STRING_AS_STRING, &value);

			dbus_message_iter_append_basic(&value, DBUS_TYPE_STRING, &ssid);
			dbus_message_iter_close_container(&type, &value);
			dbus_message_iter_close_container(&dict, &type);

			/* Security */
			dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, 0, &type);
			dbus_message_iter_append_basic(&type, DBUS_TYPE_STRING, &prop_security);
			dbus_message_iter_open_container(&type, DBUS_TYPE_VARIANT, DBUS_TYPE_INT32_AS_STRING, &value);

			dbus_message_iter_append_basic(&value, DBUS_TYPE_INT32, &security);
			dbus_message_iter_close_container(&type, &value);
			dbus_message_iter_close_container(&dict, &type);

			/* WPS */
			dbus_message_iter_open_container(&dict, DBUS_TYPE_DICT_ENTRY, 0, &type);
			dbus_message_iter_append_basic(&type, DBUS_TYPE_STRING, &prop_wps);
			dbus_message_iter_open_container(&type, DBUS_TYPE_VARIANT, DBUS_TYPE_BOOLEAN_AS_STRING, &value);

			dbus_message_iter_append_basic(&value, DBUS_TYPE_BOOLEAN, &wps);
			dbus_message_iter_close_container(&type, &value);
			dbus_message_iter_close_container(&dict, &type);
		}
	}

	dbus_message_iter_close_container(&array, &dict);

	dbus_connection_send(connection, signal, NULL);

	dbus_message_unref(signal);
	dbus_connection_unref(connection);

	g_slist_free_full(wifi_bss_info_list, g_free);
	wifi_bss_info_list = NULL;

	if (g_ssid != NULL) {
		g_free(g_ssid);
		g_ssid = NULL;
	}

	INFO("(%s)", sig_name);
}

static void __netconfig_wifi_check_security(const char *str_keymgmt, struct bss_info_t *bss_data)
{
	INFO("keymgmt : %s", str_keymgmt);

	if (strcmp(str_keymgmt, "ieee8021x") == 0) {
		bss_data->security = WIFI_SECURITY_IEEE8021X;
	} else if (strcmp(str_keymgmt, "wpa-psk") == 0) {
		bss_data->security = WIFI_SECURITY_PSK;
	} else if (strcmp(str_keymgmt, "wpa-psk-sha256") == 0) {
		bss_data->security = WIFI_SECURITY_PSK;
	} else if (strcmp(str_keymgmt, "wpa-ft-psk") == 0) {
		bss_data->security = WIFI_SECURITY_PSK;
	} else if (strcmp(str_keymgmt, "wpa-ft-eap") == 0) {
		bss_data->security = WIFI_SECURITY_IEEE8021X;
	} else if (strcmp(str_keymgmt, "wpa-eap") == 0) {
		bss_data->security = WIFI_SECURITY_IEEE8021X;
	} else if (strcmp(str_keymgmt, "wpa-eap-sha256") == 0) {
		bss_data->security = WIFI_SECURITY_IEEE8021X;
	} else if (strcmp(str_keymgmt, "wps") == 0) {
		bss_data->wps = TRUE;
	}
}

static void __netconfig_wifi_parse_keymgmt_message(DBusMessageIter *iter, struct bss_info_t *bss_data)
{
	DBusMessageIter dict, entry, array, value;
	const char *key;

	if (dbus_message_iter_get_arg_type(iter) != DBUS_TYPE_ARRAY)
		return;

	dbus_message_iter_recurse(iter, &dict);
	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		dbus_message_iter_recurse(&dict, &entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			return;

		dbus_message_iter_get_basic(&entry, &key);
		if (g_strcmp0(key, "KeyMgmt") == 0) {
			dbus_message_iter_next(&entry);

			if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_VARIANT)
				return;

			dbus_message_iter_recurse(&entry, &array);
			if (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_ARRAY)
				return;

			dbus_message_iter_recurse(&array, &value);
			while (dbus_message_iter_get_arg_type(&value) == DBUS_TYPE_STRING) {
				const char *str = NULL;

				dbus_message_iter_get_basic(&value, &str);
				if (str == NULL)
					return;

				__netconfig_wifi_check_security(str, bss_data);
				dbus_message_iter_next(&value);
			}
		}

		dbus_message_iter_next(&dict);
	}
}

gboolean netconfig_wifi_get_ssid_scan_state(void)
{
	return wifi_ssid_scan_state;
}

void netconfig_wifi_notify_ssid_scan_done(void)
{
	if (netconfig_wifi_get_ssid_scan_state() != TRUE)
		return;

	__netconfig_wifi_ssid_scan_finished();

	__netconfig_wifi_notify_ssid_scan_done();
}

void netconfig_wifi_bss_added(DBusMessage *message)
{
	DBusMessageIter iter, dict, entry;
	DBusMessageIter value, array;
	const char *key;
	struct bss_info_t *bss_info;

	if (netconfig_wifi_get_ssid_scan_state() != TRUE)
		return;

	INFO("NEW BSS added");

	if (!dbus_message_iter_init(message, &iter)) {
		DBG("Message does not have parameters");
		return;
	}

	dbus_message_iter_next(&iter);

	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY) {
		DBG("Invalid message type");
		return;
	}

	bss_info = g_try_new0(struct bss_info_t, 1);
	if (bss_info == NULL)
		return;

	dbus_message_iter_recurse(&iter, &dict);
	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		dbus_message_iter_recurse(&dict, &entry);

		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_STRING)
			return;

		dbus_message_iter_get_basic(&entry, &key);
		if (key == NULL)
			return;

		dbus_message_iter_next(&entry);
		if (dbus_message_iter_get_arg_type(&entry) != DBUS_TYPE_VARIANT)
			return;

		dbus_message_iter_recurse(&entry, &value);

		if (g_strcmp0(key, "SSID") == 0) {
			unsigned char *ssid;
			int ssid_len;

			dbus_message_iter_recurse(&value, &array);
			dbus_message_iter_get_fixed_array(&array, &ssid, &ssid_len);

			if (ssid_len > 0 && ssid_len < 33)
				memcpy(bss_info->ssid, ssid, ssid_len);
			else
				memset(bss_info->ssid, 0, sizeof(bss_info->ssid));
		} else if (g_strcmp0(key, "Privacy") == 0) {
			dbus_bool_t privacy = FALSE;

			dbus_message_iter_get_basic(&value, &privacy);
			bss_info->privacy = privacy;
		} else if ((g_strcmp0(key, "RSN") == 0) || (g_strcmp0(key, "WPA") == 0)) {

			__netconfig_wifi_parse_keymgmt_message(&value, bss_info);
		} else if (g_strcmp0(key, "IEs") == 0) {
			unsigned char *ie;
			int ie_len;

			dbus_message_iter_recurse(&value, &array);
			dbus_message_iter_get_fixed_array(&array, &ie, &ie_len);
		}

		dbus_message_iter_next(&dict);
	}

	if (bss_info->ssid[0] == '\0') {
		g_free(bss_info);
		return;
	}

	if (bss_info->security == WIFI_SECURITY_UNKNOWN) {
		if (bss_info->privacy == TRUE)
			bss_info->security = WIFI_SECURITY_WEP;
		else
			bss_info->security = WIFI_SECURITY_NONE;
	}

	wifi_bss_info_list = g_slist_append(wifi_bss_info_list, bss_info);
}

gboolean netconfig_wifi_ssid_scan(const char *ssid)
{
	const char *if_path;
	static char *scan_ssid = NULL;

	netconfig_wifi_bgscan_stop();

	if (ssid != NULL) {
		g_free(scan_ssid);
		scan_ssid = g_strdup(ssid);
	}

	if (scan_ssid == NULL)
		goto error;

	if_path = netconfig_wifi_get_supplicant_interface();
	if (if_path == NULL) {
		DBG("Fail to get wpa_supplicant DBus path");
		goto error;
	}

	if (netconfig_wifi_get_scanning() == TRUE) {
		DBG("Wi-Fi scan in progress, %s scan will be delayed", scan_ssid);
		return TRUE;
	}

	if (wifi_bss_info_list) {
		g_slist_free_full(wifi_bss_info_list, g_free);
		wifi_bss_info_list = NULL;
	}

	INFO("Start Wi-Fi scan with %s(%d)", scan_ssid, strlen(scan_ssid));
	if (__netconfig_wifi_invoke_ssid_scan(if_path,
							(const char *)scan_ssid) == TRUE) {
		__netconfig_wifi_ssid_scan_started();

		g_free(scan_ssid);
		scan_ssid = NULL;

		return TRUE;
	}

error:
	if (scan_ssid != NULL) {
		g_free(scan_ssid);
		scan_ssid = NULL;
	}

	netconfig_wifi_bgscan_start(FALSE);

	return FALSE;
}

gboolean netconfig_iface_wifi_request_specific_scan(NetconfigWifi *wifi,
		gchar *ssid, GError **error)
{
	g_return_val_if_fail(wifi != NULL, FALSE);
	g_return_val_if_fail(ssid != NULL, FALSE);

	return netconfig_wifi_ssid_scan((const char *)ssid);
}
