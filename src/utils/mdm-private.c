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

/* MDM security is supported in private only,
 * do not make in public and share usage.
 *
 * For the purpose of TIZEN release
 * 1. eliminate libmdm-dev Build-Depends in debian/control
 * 2. eliminate pkgconfig(mdm) BuildRequire in packaging/net-config.spec
 * 3. eliminate mdm pkgs REQUIRED in CMakeLists.txt
 * 4. eliminate "#include <mdm.h>" in mdm-private.c
 * 5. eliminate implementation body of netconfig_is_wifi_allowed()
 * 6. make netconfig_is_wifi_allowed, witch always return TRUE such as
 * gboolean netconfig_is_wifi_allowed(void)
 * {
 * 		return TRUE;
 * }
 */

#include <mdm.h>

#include "log.h"
#include "netdbus.h"
#include "mdm-private.h"

enum netconfig_wifi_sec_level {
	WIFI_SEC_LEVEL_UNKNOWN = 0,
	WIFI_SEC_LEVEL_NONE = 1,
	WIFI_SEC_LEVEL_WEP = 2,
	WIFI_SEC_LEVEL_PSK = 3,
	WIFI_SEC_LEVEL_EAP_PEAP = 4,
	WIFI_SEC_LEVEL_EAP_TLS = 5,
	WIFI_SEC_LEVEL_EAP_TTLS = 6,
	WIFI_SEC_LEVEL_EAP_SIM = 7,
	WIFI_SEC_LEVEL_EAP_AKA = 8,
};

#if defined MDM_PHASE_2
static enum netconfig_wifi_sec_level __netconfig_get_eap_level(const char *eap)
{
	if (eap == NULL)
		return WIFI_SEC_LEVEL_EAP_PEAP;
	else if (g_str_equal(eap, "peap") == TRUE)
		return WIFI_SEC_LEVEL_EAP_PEAP;
	else if (g_str_equal(eap, "tls") == TRUE)
		return WIFI_SEC_LEVEL_EAP_TLS;
	else if (g_str_equal(eap, "ttls") == TRUE)
		return WIFI_SEC_LEVEL_EAP_TTLS;
	else if (g_str_equal(eap, "sim") == TRUE)
		return WIFI_SEC_LEVEL_EAP_SIM;
	else if (g_str_equal(eap, "aka") == TRUE)
		return WIFI_SEC_LEVEL_EAP_AKA;
	else
		return WIFI_SEC_LEVEL_EAP_PEAP;
}

static enum netconfig_wifi_sec_level __netconfig_get_sec_level(
		const char *security, const char *eap)
{
	if (g_str_equal(security, "none") == TRUE)
		return WIFI_SEC_LEVEL_NONE;
	else if (g_str_equal(security, "wep") == TRUE)
		return WIFI_SEC_LEVEL_WEP;
	else if (g_str_equal(security, "psk") == TRUE)
		return WIFI_SEC_LEVEL_PSK;
	else if (g_str_equal(security, "ieee8021x") == TRUE)
		return __netconfig_get_eap_level(eap);

	return WIFI_SEC_LEVEL_UNKNOWN;
}

static gboolean __netconfig_is_ap_allowed(const char *ssid,
		const char *security, const char *eap)
{
	gboolean ret = FALSE;
	mdm_result_t result;

	result = mdm_get_service();

	if (result != MDM_RESULT_SUCCESS) {
		ret = TRUE;
		goto done;
	}

	mdm_status_t rv = mdm_is_network_blocked(ssid);

	if (rv == MDM_TRUE)
		goto done;

	mdm_wifi_sec_type_e sec_type = mdm_get_minimum_required_security();
	enum netconfig_wifi_sec_level sec_level =
			__netconfig_get_sec_level(security, eap);

	switch (sec_type) {
	case SECURITY_LEVEL_NONE:
	case SECURITY_LEVEL_OPEN:
		break;
	case SECURITY_LEVEL_WEP:
		if (sec_level < WIFI_SEC_LEVEL_WEP)
			goto done;
		break;
	case SECURITY_LEVEL_WPA_PSK:
	case SECURITY_LEVEL_WPA2_PSK:
		if (sec_level < WIFI_SEC_LEVEL_PSK)
			goto done;
		break;
	case SECURITY_LEVEL_EAP_PEAP:
		if (sec_level < WIFI_SEC_LEVEL_EAP_PEAP)
			goto done;
		break;
	case SECURITY_LEVEL_EAP_TLS:
		if (sec_level < WIFI_SEC_LEVEL_EAP_TLS)
			goto done;
		break;
	case SECURITY_LEVEL_EAP_TTLS:
		if (sec_level < WIFI_SEC_LEVEL_EAP_TTLS)
			goto done;
		break;
	case SECURITY_LEVEL_EAP_SIM:
		if (sec_level < WIFI_SEC_LEVEL_EAP_SIM)
			goto done;
		break;
	case SECURITY_LEVEL_EAP_AKA:
		if (sec_level < WIFI_SEC_LEVEL_EAP_AKA)
			goto done;
		break;
	default:
		break;
	}

	ret = TRUE;

done:
	mdm_release_service();

	return ret;
}

static gboolean __netconfig_get_ap_info(const char *path, char **essid,
		char **security, char **eap)
{
	gboolean ret = FALSE;
	DBusMessage *message = NULL;
	DBusMessageIter iter, array;

	if (essid == NULL || security == NULL || eap == NULL ||
	    netconfig_is_wifi_profile(path) != TRUE) {
		ERR("Invalid parameter");
		goto done;
	}

	message = netconfig_invoke_dbus_method(CONNMAN_SERVICE, path,
			CONNMAN_SERVICE_INTERFACE, "GetProperties", NULL);
	if (message == NULL) {
		ERR("Failed to get service properties");
		goto done;
	}

	if (dbus_message_get_type(message) == DBUS_MESSAGE_TYPE_ERROR) {
		const char *ptr = dbus_message_get_error_name(message);
		ERR("Error!!! Error message received [%s]", ptr);
		goto done;
	}

	dbus_message_iter_init(message, &iter);
	dbus_message_iter_recurse(&iter, &array);

	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, variant, sub_array;
		const char *key = NULL, *value = NULL;

		dbus_message_iter_recurse(&array, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &variant);

		if (g_str_equal(key, "Name") == TRUE) {
			if (dbus_message_iter_get_arg_type(&variant) == DBUS_TYPE_STRING) {
				dbus_message_iter_get_basic(&variant, &value);

				if (value) {
					*essid = g_strdup(value);
				}
			}
		} else if (g_str_equal(key, "Security") == TRUE) {
			dbus_message_iter_recurse(&variant, &sub_array);

			if (dbus_message_iter_get_arg_type(&sub_array) ==
					DBUS_TYPE_STRING) {
				dbus_message_iter_get_basic(&sub_array, &value);

				if (value) {
					*security = g_strdup(value);
				}
			}
		} else if (g_str_equal(key, "EAP") == TRUE) {
			if (dbus_message_iter_get_arg_type(&variant) == DBUS_TYPE_STRING) {
				dbus_message_iter_get_basic(&variant, &value);

				if (value) {
					*eap = g_strdup(value);
				}
			}
		}

		dbus_message_iter_next(&array);
	}

	ret = TRUE;

done:
	if (message != NULL)
		dbus_message_unref(message);

	return ret;
}

static void __netconfig_disconnect_ap(const char *path)
{
	DBusMessage *message = NULL;

	if (netconfig_is_wifi_profile(path) != TRUE) {
		ERR("Invalid parameter");
		return;
	}

	message = netconfig_invoke_dbus_method(CONNMAN_SERVICE, path,
			CONNMAN_SERVICE_INTERFACE, "Disconnect", NULL);

	if (message == NULL)
		return;

	if (dbus_message_get_type(message) == DBUS_MESSAGE_TYPE_ERROR) {
		const char *err_msg = dbus_message_get_error_name(message);
		ERR("Error!!! Error message received %s", err_msg);
	}

	if (message != NULL)
		dbus_message_unref(message);
}
#endif

gboolean netconfig_is_wifi_allowed(void)
{
	gboolean ret = TRUE;

	mdm_result_t result;

	result = mdm_get_service();

	if (result == MDM_RESULT_SUCCESS) {
		if (mdm_get_allow_wifi() == MDM_RESTRICTED)
			ret = FALSE;

		mdm_release_service();
	}

	return ret;
}

void netconfig_check_allowed_ap(const char *path)
{
#if defined MDM_PHASE_2
	gboolean ret = FALSE;
	char *essid = NULL;
	char *security = NULL;
	char *eap = NULL;

	ret = __netconfig_get_ap_info(path, &essid, &security, &eap);

	if (ret == FALSE)
		return;

	ret = __netconfig_is_ap_allowed(essid, security, eap);
	g_free(essid);
	g_free(security);
	g_free(eap);

	if (ret == TRUE)
		return;

	__netconfig_disconnect_ap(path);
#endif
}
