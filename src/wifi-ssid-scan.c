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

typedef enum {
	WIFI_SECURITY_UNKNOWN = 0x00,
	WIFI_SECURITY_NONE = 0x01,
	WIFI_SECURITY_WEP = 0x02,
	WIFI_SECURITY_PSK = 0x03,
	WIFI_SECURITY_IEEE8021X = 0x04,
} wifi_security_e;

typedef struct {
	unsigned char ssid[33];
	wifi_security_e security;
	gboolean privacy;
	gboolean wps;
} bss_info_t;

static gboolean g_ssid_scan_state = FALSE;
static GSList *bss_info_list = NULL;
static guint ssid_scan_timer = 0;
static char *g_ssid = NULL;

static void __check_security(const char *str_keymgmt, bss_info_t *bss_info)
{
	INFO("keymgmt : %s", str_keymgmt);

	if (g_strcmp0(str_keymgmt, "ieee8021x") == 0) {
		bss_info->security = WIFI_SECURITY_IEEE8021X;
	} else if (g_strcmp0(str_keymgmt, "wpa-psk") == 0) {
		bss_info->security = WIFI_SECURITY_PSK;
	} else if (g_strcmp0(str_keymgmt, "wpa-psk-sha256") == 0) {
		bss_info->security = WIFI_SECURITY_PSK;
	} else if (g_strcmp0(str_keymgmt, "wpa-ft-psk") == 0) {
		bss_info->security = WIFI_SECURITY_PSK;
	} else if (g_strcmp0(str_keymgmt, "wpa-ft-eap") == 0) {
		bss_info->security = WIFI_SECURITY_IEEE8021X;
	} else if (g_strcmp0(str_keymgmt, "wpa-eap") == 0) {
		bss_info->security = WIFI_SECURITY_IEEE8021X;
	} else if (g_strcmp0(str_keymgmt, "wpa-eap-sha256") == 0) {
		bss_info->security = WIFI_SECURITY_IEEE8021X;
	} else if (g_strcmp0(str_keymgmt, "wps") == 0) {
		bss_info->wps = TRUE;
	}
}

static gboolean __ssid_scan_timeout(gpointer data)
{
	wifi_ssid_scan_emit_scan_completed();

	return FALSE;
}

static void _start_ssid_scan_timer(void)
{
	INFO("Wi-Fi SSID scan started");
	g_ssid_scan_state = TRUE;

	netconfig_start_timer_seconds(5, __ssid_scan_timeout, NULL, &ssid_scan_timer);
}

static void _stop_ssid_scan_timer(void)
{
	INFO("Wi-Fi SSID scan finished");
	g_ssid_scan_state = FALSE;

	netconfig_stop_timer(&ssid_scan_timer);
}

static void _parse_keymgmt_message(GVariant *param, bss_info_t *bss_info)
{
	GVariantIter *iter1;
	GVariant *var;
	gchar *key;

	g_variant_get(param, "a{sv}", &iter1);
	while (g_variant_iter_loop(iter1, "{sv}", &key, &var)) {
		if (g_strcmp0(key, "KeyMgmt") == 0) {//check this :iterate
			GVariantIter *iter2;
			g_variant_get(var, "as", &iter2);
			char *str;
			while (g_variant_iter_loop(iter2, "s", &str)) {
				if (str == NULL) {
					break;
				}
				__check_security(str, bss_info);
			}
			g_variant_iter_free (iter2);
		}
	}

	g_variant_iter_free (iter1);

	return;
}

static gboolean _request_ssid_scan(const char *object_path, const char *ssid)
{
	/* TODO: Revise following code */

#define NETCONFIG_DBUS_REPLY_TIMEOUT (10 * 1000)
	GDBusConnection *connection = NULL;
	GVariant *reply = NULL;
	GVariant *params = NULL;
	GError *error = NULL;
	GVariantBuilder *builder1 = NULL;
	GVariantBuilder *builder2 = NULL;
	GVariantBuilder *builder3 = NULL;
	const gchar *key1 = "Type";
	const gchar *val1 = "active";
	const gchar *key2 = "SSIDs";
	int i = 0;

	connection = netdbus_get_connection();
	if (connection == NULL) {
		DBG("Failed to get GDBusconnection");
		return FALSE;
	}

	builder1 = g_variant_builder_new(G_VARIANT_TYPE ("a{sv}"));
	g_variant_builder_add(builder1, "{sv}", key1, g_variant_new_string(val1));

	builder2 = g_variant_builder_new(G_VARIANT_TYPE ("aay"));
	builder3 = g_variant_builder_new (G_VARIANT_TYPE ("ay"));

	for (i = 0; i < strlen(ssid); i++) {
		g_variant_builder_add (builder3, "y", ssid[i]);
	}

	g_variant_builder_add(builder2, "@ay", g_variant_builder_end(builder3));
	g_variant_builder_add(builder1, "{sv}", key2, g_variant_builder_end(builder2));

	params = g_variant_new("(@a{sv})", g_variant_builder_end(builder1));

	g_variant_builder_unref(builder1);
	g_variant_builder_unref(builder2);
	g_variant_builder_unref(builder3);

	reply = g_dbus_connection_call_sync(
			connection,
			SUPPLICANT_SERVICE,
			object_path,
			SUPPLICANT_INTERFACE ".Interface",
			"Scan",
			params,
			NULL,
			G_DBUS_CALL_FLAGS_NONE,
			NETCONFIG_DBUS_REPLY_TIMEOUT,
			netdbus_get_cancellable(),
			&error);

	if (reply == NULL) {
		if (error != NULL) {
			ERR("Error!!! dbus_connection_send_with_reply_and_block() failed. "
					"DBus error [%d: %s]", error->code, error->message);
			g_error_free(error);
		} else
			ERR("Error!!! Failed to get properties");

		return FALSE;
	}

	if (g_ssid != NULL) {
		g_free(g_ssid);
	}

	g_ssid = g_strdup(ssid);

	g_variant_unref(reply);

	return TRUE;
}

static void _emit_ssid_scan_completed(void)
{
	GVariantBuilder *builder = NULL;
	GSList* list = NULL;
	const char *prop_ssid = "ssid";
	const char *prop_security = "security";
	const char *prop_wps = "wps";

	builder = g_variant_builder_new(G_VARIANT_TYPE ("a{sv}"));
	for (list = bss_info_list; list != NULL; list = list->next) {
		bss_info_t *bss_info = (bss_info_t *)list->data;
		if (bss_info && g_strcmp0((char *)bss_info->ssid, g_ssid) == 0) {
			const gchar *ssid = (char *)bss_info->ssid;
			wifi_security_e security = bss_info->security;
			gboolean wps = bss_info->wps;
			DBG("BSS found; SSID:%s security:%d WPS:%d", ssid, security, wps);
			g_variant_builder_add(builder, "{sv}", prop_ssid, g_variant_new_string(ssid));
			g_variant_builder_add(builder, "{sv}", prop_security, g_variant_new_int32(security));
			/* WPS */
			g_variant_builder_add(builder, "{sv}", prop_wps, g_variant_new_boolean(wps));
		}
	}

	wifi_emit_specific_scan_completed((Wifi *)get_wifi_object(), g_variant_builder_end(builder));

	if (builder)
		g_variant_builder_unref(builder);

	if (bss_info_list != NULL) {
		g_slist_free_full(bss_info_list, g_free);
		bss_info_list = NULL;
	}

	if (g_ssid != NULL) {
		g_free(g_ssid);
		g_ssid = NULL;
	}

	INFO("SpecificScanCompleted");

	return;
}

gboolean wifi_ssid_scan(const char *ssid)
{
	const char *if_path;
	static char *scan_ssid = NULL;

	netconfig_wifi_bgscan_stop();

	if (ssid != NULL) {
		if (scan_ssid != NULL) {
			g_free(scan_ssid);
		}
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
		g_free(scan_ssid);
		return TRUE;
	}

	if (bss_info_list) {
		g_slist_free_full(bss_info_list, g_free);
		bss_info_list = NULL;
	}

	INFO("Start Wi-Fi scan with %s(%d)", scan_ssid, strlen(scan_ssid));
	if (_request_ssid_scan(if_path, (const char *)scan_ssid) == TRUE) {
		_start_ssid_scan_timer();
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

gboolean wifi_ssid_scan_get_state(void)
{
	return g_ssid_scan_state;
}

void wifi_ssid_scan_emit_scan_completed(void)
{
	if (g_ssid_scan_state != TRUE)
		return;

	_stop_ssid_scan_timer();
	_emit_ssid_scan_completed();
}

void wifi_ssid_scan_add_bss(GVariant *message)
{
	GVariantIter *iter;
	GVariant *value;
	gchar *path = NULL;
	gchar *key;
	bss_info_t *bss_info;

	if (g_ssid_scan_state != TRUE)
		return;

	INFO("NEW BSS added");

	if (message == NULL) {
		DBG("Message does not have parameters");
		return;
	}

	if (path != NULL)
		INFO("Object path of BSS added is %s",path);

	bss_info = g_try_new0(bss_info_t, 1);
	if (bss_info == NULL)
		return;

	g_variant_get(message, "(oa{sv})", &path, &iter);
	while (g_variant_iter_loop(iter, "{sv}", &key, &value)) {
		if (g_strcmp0(key, "SSID") == 0) {
			const guchar *ssid;
			gsize ssid_len;
			ssid = g_variant_get_fixed_array(value, &ssid_len, sizeof(guchar));
			if (ssid != NULL && ssid_len > 0 && ssid_len < 33)
				memcpy(bss_info->ssid, ssid, ssid_len);
			else
				memset(bss_info->ssid, 0, sizeof(bss_info->ssid));
		} else if (g_strcmp0(key, "Privacy") == 0) {
			gboolean privacy = FALSE;
			privacy = g_variant_get_boolean(value);
			bss_info->privacy = privacy;
		} else if ((g_strcmp0(key, "RSN") == 0) || (g_strcmp0(key, "WPA") == 0)) {
			_parse_keymgmt_message(value, bss_info);
		} else if (g_strcmp0(key, "IEs") == 0) {
			const guchar *ie;
			gsize ie_len;
			ie = g_variant_get_fixed_array(value, &ie_len, sizeof(guchar));
			DBG("The IE : %s",ie);
		}
	}

	g_variant_iter_free(iter);
	if (path)
		g_free(path);

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

	bss_info_list = g_slist_append(bss_info_list, bss_info);
}

gboolean handle_request_specific_scan(Wifi *wifi,
		GDBusMethodInvocation *context, const gchar *ssid)
{
	gboolean result = FALSE;

	g_return_val_if_fail(wifi != NULL, FALSE);
	g_return_val_if_fail(ssid != NULL, FALSE);

	result = wifi_ssid_scan((const char *)ssid);

	if (result != TRUE) {
		netconfig_error_dbus_method_return(context, NETCONFIG_ERROR_INTERNAL, "FailSpecificScan");
	} else {
		wifi_complete_request_wps_scan(wifi, context);
	}

	return result;
}
