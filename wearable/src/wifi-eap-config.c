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
#include <stdio.h>
#include <unistd.h>

#include "log.h"
#include "util.h"
#include "netdbus.h"
#include "wifi-agent.h"
#include "wifi-state.h"
#include "wifi-eap-config.h"

#define CONNMAN_STORAGEDIR					"/var/lib/connman"

#define CONNMAN_CONFIG_FIELD_TYPE			"Type"
#define CONNMAN_CONFIG_FIELD_NAME			"Name"
#define CONNMAN_CONFIG_FIELD_SSID			"SSID"
#define CONNMAN_CONFIG_FIELD_EAP_METHOD		"EAP"
#define CONNMAN_CONFIG_FIELD_IDENTITY		"Identity"
#define CONNMAN_CONFIG_FIELD_PASSPHRASE		"Passphrase"
#define CONNMAN_CONFIG_FIELD_PHASE2			"Phase2"
#define CONNMAN_CONFIG_FIELD_CA_CERT_FILE			"CACertFile"
#define CONNMAN_CONFIG_FIELD_CLIENT_CERT_FILE		"ClientCertFile"
#define CONNMAN_CONFIG_FIELD_PVT_KEY_FILE			"PrivateKeyFile"
#define CONNMAN_CONFIG_FIELD_PVT_KEY_PASSPHRASE		"PrivateKeyPassphrase"

static char *__get_encoded_ssid(const char *name)
{
	char *str = NULL;
	char *pstr = NULL;
	int i = 0, len = 0;

	if (name == NULL)
		return NULL;

	len = strlen(name);

	str = g_try_malloc0(len * 2 + 1);
	if (str == NULL)
		return NULL;

	pstr = str;
	for (i = 0; i < len; i++) {
		g_snprintf(pstr, 3, "%02x", name[i]);
		pstr += 2;
	}

	return str;
}

static int __config_save(const char *ssid, GKeyFile *keyfile)
{
	gchar *data = NULL;
	gchar *config_file = NULL;
	gsize length = 0;
	FILE *file = NULL;
	int err = 0;

	config_file = g_strdup_printf("%s/%s.config", CONNMAN_STORAGEDIR, ssid);
	if (config_file == NULL) {
		err = -ENOMEM;
		goto out;
	}

	data = g_key_file_to_data(keyfile, &length, NULL);

	file = fopen(config_file, "w");
	if (file == NULL) {
		ERR("Failed to open %s", config_file);

		err = -EIO;
		goto out;
	}

	if (fputs(data, file) < 0) {
		ERR("Failed to write %s", config_file);

		err = -EIO;
		goto out;
	}

out:
	if (file != NULL)
		fclose(file);

	g_free(data);
	g_free(config_file);

	return err;
}

static int __config_delete(const char *ssid)
{
	gchar *config_file = NULL;
	int err = 0;

	config_file = g_strdup_printf("%s/%s.config", CONNMAN_STORAGEDIR, ssid);
	if(config_file == NULL)
		return -ENOMEM;

	if (remove(config_file) < 0) {
		err = -EIO;
		goto out;
	}

out:
	g_free(config_file);

	return err;
}

static gboolean __netconfig_create_config(GHashTable *fields)
{
	GKeyFile *keyfile = NULL;
	GHashTableIter iter;
	gchar *encoded_ssid = NULL;
	gchar *group_name = NULL;
	gpointer field, value;
	gboolean updated = FALSE;

	g_hash_table_iter_init(&iter, fields);
	while (g_hash_table_iter_next(&iter, &field, &value)) {
		if (value != NULL) {
			if (g_strcmp0(field, CONNMAN_CONFIG_FIELD_NAME) == 0) {
				encoded_ssid = __get_encoded_ssid((const char *)value);
				break;
			} else if (g_strcmp0(field, CONNMAN_CONFIG_FIELD_SSID) == 0) {
				encoded_ssid = g_strdup((const char *)value);
				break;
			}
		}
	}

	if (encoded_ssid == NULL) {
		ERR("Failed to fetch SSID");
		goto out;
	}

	/* Create unique service group name */
	group_name = g_strdup_printf("service_%s", encoded_ssid);
	if (group_name == NULL) {
		ERR("Failed to create service group name");
		goto out;
	}

	keyfile = g_key_file_new();
	if (keyfile == NULL) {
		ERR("Failed to g_key_file_new");
		goto out;
	}

	g_hash_table_iter_init(&iter, fields);
	while (g_hash_table_iter_next(&iter, &field, &value)) {
		if (g_strcmp0(field, CONNMAN_CONFIG_FIELD_SSID) == 0 ||
				g_strcmp0(field, CONNMAN_CONFIG_FIELD_EAP_METHOD) == 0 ||
				g_strcmp0(field, CONNMAN_CONFIG_FIELD_PHASE2) == 0)
			DBG("field: %s, value: %s", field, value);
		else
			DBG("field: %s, value:", field);

		if (value != NULL)
			g_key_file_set_string(keyfile, group_name, field, value);
	}

	if (__config_save((const char *)encoded_ssid, keyfile) == 0) {
		DBG("Successfully created %s", encoded_ssid);
		updated = TRUE;
	}

out:
	if (keyfile != NULL)
		g_key_file_free(keyfile);

	g_free(group_name);
	g_free(encoded_ssid);

	return updated;
}

static gboolean __netconfig_delete_config(const char *profile)
{
	char *wifi_ident = NULL;
	char *essid = NULL;
	char *mode = NULL;
	char *ssid = NULL;
	int ssid_len = 0;

	if (NULL == profile) {
		ERR("Invalid profile name");
		return FALSE;
	}

	wifi_ident = strstr(profile, "wifi_");
	if (wifi_ident == NULL) {
		ERR("Invalid profile name");
		return FALSE;
	}

	essid = strchr(wifi_ident + 5, '_');
	if (essid == NULL) {
		ERR("Invalid profile name");
		return FALSE;
	}

	essid++;
	mode = strchr(essid, '_');

	ssid_len = mode - essid;

	ssid = g_try_malloc0(ssid_len + 1);
	if (ssid == NULL) {
		ERR("Memory allocation failed");
		return FALSE;
	}

	g_strlcpy(ssid, essid, ssid_len + 1); /* include NULL-terminated */
	if (__config_delete((const char *)ssid) < 0) {
		g_free(ssid);
		return FALSE;
	}

	DBG("Successfully deleted %s with length %d", ssid, ssid_len);

	g_free(ssid);
	return TRUE;
}

static void __netconfig_eap_state(
		enum netconfig_wifi_service_state state, void *user_data);

static struct netconfig_wifi_state_notifier netconfig_eap_notifier = {
		.netconfig_wifi_state_changed = __netconfig_eap_state,
		.user_data = NULL,
};

static void __netconfig_eap_state(
		enum netconfig_wifi_service_state state, void *user_data)
{
	const char *wifi_profile = (const char *)user_data;

	if (wifi_profile == NULL) {
		netconfig_wifi_state_notifier_unregister(&netconfig_eap_notifier);
		return;
	}

	if (state != NETCONFIG_WIFI_CONNECTED && state != NETCONFIG_WIFI_FAILURE)
		return;

	if (state == NETCONFIG_WIFI_FAILURE)
		__netconfig_delete_config(wifi_profile);

	g_free(netconfig_eap_notifier.user_data);
	netconfig_eap_notifier.user_data = NULL;

	netconfig_wifi_state_notifier_unregister(&netconfig_eap_notifier);
}

gboolean netconfig_iface_wifi_create_config(NetconfigWifi *wifi,
		gchar *service, GHashTable *fields,
		DBusGMethodInvocation *context)
{
	GError *error;
	gboolean updated = FALSE;
	gboolean reply = FALSE;

	g_return_val_if_fail(wifi != NULL, FALSE);

	DBG("Set agent fields for %s", service);

	if (netconfig_is_wifi_profile(service) != TRUE) {
		error = g_error_new(DBUS_GERROR,
				DBUS_GERROR_AUTH_FAILED,
				CONNMAN_ERROR_INTERFACE ".InvalidService");

		dbus_g_method_return_error(context, error);
		g_clear_error(&error);

		return reply;
	}

	updated = __netconfig_create_config(fields);
	if (updated == TRUE) {
		dbus_g_method_return(context);

		if (g_strstr_len(service, strlen(service), "_hidden_") != NULL) {
			GHashTableIter iter;
			gpointer field, value;
			const char *name = NULL;
			const char *identity = NULL;
			const char *passphrase = NULL;

			g_hash_table_iter_init(&iter, fields);

			while (g_hash_table_iter_next(&iter, &field, &value)) {
				if (g_strcmp0(field, CONNMAN_CONFIG_FIELD_NAME) == 0)
					name = (const char *)value;
				else if (g_strcmp0(field, CONNMAN_CONFIG_FIELD_SSID) == 0)
					name = (const char *)value;
				else if (g_strcmp0(field, CONNMAN_CONFIG_FIELD_IDENTITY) == 0)
					identity = (const char *)value;
				else if (g_strcmp0(field, CONNMAN_CONFIG_FIELD_PASSPHRASE) == 0)
					passphrase = (const char *)value;
			}

			netconfig_wifi_set_agent_field_for_eap_network(
									name, identity, passphrase);
		}

		reply = netconfig_invoke_dbus_method_nonblock(CONNMAN_SERVICE,
				service, CONNMAN_SERVICE_INTERFACE, "Connect", NULL, NULL);

		if (netconfig_eap_notifier.user_data != NULL) {
			g_free(netconfig_eap_notifier.user_data);
			netconfig_eap_notifier.user_data = NULL;

			netconfig_wifi_state_notifier_unregister(&netconfig_eap_notifier);
		}

		netconfig_eap_notifier.user_data = g_strdup(service);
		netconfig_wifi_state_notifier_register(&netconfig_eap_notifier);
	} else {
		error = g_error_new(DBUS_GERROR,
				DBUS_GERROR_AUTH_FAILED,
				CONNMAN_ERROR_INTERFACE ".InvalidArguments");

		dbus_g_method_return_error(context, error);
		g_clear_error(&error);
	}

	if (reply != TRUE)
		ERR("Fail to connect %s", service);

	return reply;
}

gboolean netconfig_iface_wifi_delete_config(NetconfigWifi *wifi,
		gchar *profile,
		DBusGMethodInvocation *context)
{
	g_return_val_if_fail(wifi != NULL, FALSE);

	dbus_g_method_return(context);

	return __netconfig_delete_config((const char *)profile);
}
