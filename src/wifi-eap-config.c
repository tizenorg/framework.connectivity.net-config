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
#include <sys/stat.h>

#include "log.h"
#include "util.h"
#include "netdbus.h"
#include "wifi-agent.h"
#include "wifi-state.h"
#include "wifi-config.h"
#include "wifi-eap-config.h"
#include "neterror.h"

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
#define CONNMAN_CONFIG_FIELD_KEYMGMT_TYPE			"KeymgmtType"

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

	/* Do POSIX file operation to create and remove config files,
	 * Do not use g_file_set_contents, it breaks inotify operations */
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
	int err = 0;
	gchar *group_name = NULL;
	gchar *config_file = NULL;
	gchar *dirname = NULL;
	gchar *cert_path = NULL;
	GKeyFile *keyfile = NULL;
	GError *error = NULL;

	config_file = g_strdup_printf("%s/%s.config", CONNMAN_STORAGEDIR, ssid);
	if (config_file == NULL)
		return -ENOMEM;

	keyfile = g_key_file_new();

	if (g_key_file_load_from_file(keyfile, config_file, 0, &error) != TRUE) {
		ERR("Unable to load %s[%s]", config_file, error->message);
		g_clear_error(&error);

		err = -EIO;
		goto out;
	}

	group_name = g_strdup_printf("service_%s", ssid);

	cert_path = g_key_file_get_string(keyfile, group_name,
			CONNMAN_CONFIG_FIELD_CA_CERT_FILE, NULL);
	DBG("Temporal %s", cert_path);
	if (cert_path != NULL && remove(cert_path) != 0)
		ERR("Failed to remove %s", cert_path);
	g_free(cert_path);

	cert_path = g_key_file_get_string(keyfile, group_name,
			CONNMAN_CONFIG_FIELD_CLIENT_CERT_FILE, NULL);
	DBG("Temporal %s", cert_path);
	if (cert_path != NULL && remove(cert_path) != 0)
		ERR("Failed to remove %s", cert_path);
	g_free(cert_path);

	cert_path = g_key_file_get_string(keyfile, group_name,
			CONNMAN_CONFIG_FIELD_PVT_KEY_FILE, NULL);
	DBG("Temporal %s", cert_path);
	if (cert_path != NULL && remove(cert_path) != 0)
		ERR("Failed to remove %s", cert_path);
	g_free(cert_path);

	cert_path = g_key_file_get_string(keyfile, group_name,
			CONNMAN_CONFIG_FIELD_PVT_KEY_PASSPHRASE, NULL);
	DBG("Temporal %s", cert_path);
	if (cert_path != NULL && remove(cert_path) != 0)
		ERR("Failed to remove %s", cert_path);
	g_free(cert_path);

	dirname = g_strdup_printf("%s/%s", WIFI_CERT_STORAGEDIR, ssid);
	if (dirname != NULL) {
		if (g_file_test(dirname, G_FILE_TEST_EXISTS) == TRUE)
			if (g_file_test(dirname, G_FILE_TEST_IS_DIR) == TRUE)
				rmdir(dirname);

		g_free(dirname);
	}

	if (remove(config_file) != 0) {
		err = -EIO;
		goto out;
	}

out:
	g_key_file_free(keyfile);
	g_free(config_file);
	g_free(group_name);

	return err;
}

static gboolean __netconfig_copy_config(const char *src, const char *dst)
{
	gchar *buf = NULL;
	gsize length = 0;
	GError *error = NULL;
	gboolean result;

	result = g_file_get_contents(src, &buf, &length, &error);
	if (result != TRUE) {
		ERR("Failed to read %s[%s]", error->message);
		g_error_free(error);

		return result;
	}

	result = g_file_set_contents(dst, buf, length, &error);
	if (result != TRUE) {
		ERR("Failed to write %s[%s]", error->message);
		g_error_free(error);
	}

	INFO("Successfully installed[%d]", length);
	g_free(buf);

	if (remove(src) != 0)
		WARN("Failed to remove %s", src);

	return result;
}

static gboolean __netconfig_create_config(GVariant *fields)
{
	GKeyFile *keyfile = NULL;
	GVariantIter *iter;
	gchar *encoded_ssid = NULL;
	gchar *dirname = NULL;
	gchar *group_name = NULL;
	gchar *field, *value;
	gboolean updated = FALSE;
	gchar *cert_file = NULL;
	gchar *cert_path = NULL;
	int err = 0;

	g_variant_get(fields, "a{ss}", &iter);
	while (g_variant_iter_loop(iter, "{ss}", &field, &value)) {
		if (value != NULL) {
			if (g_strcmp0(field, CONNMAN_CONFIG_FIELD_NAME) == 0) {
				encoded_ssid = __get_encoded_ssid(value);

				g_free(value);
				g_free(field);
				break;
			} else if (g_strcmp0(field, CONNMAN_CONFIG_FIELD_SSID) == 0) {
				encoded_ssid = g_strdup(value);

				g_free(field);
				g_free(value);
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

	g_variant_iter_free(iter);

	g_variant_get(fields, "a{ss}", &iter);
	while (g_variant_iter_loop(iter, "{ss}", &field, &value)) {
		if (g_strcmp0(field, CONNMAN_CONFIG_FIELD_SSID) == 0 ||
				g_strcmp0(field, CONNMAN_CONFIG_FIELD_EAP_METHOD) == 0 ||
				g_strcmp0(field, CONNMAN_CONFIG_FIELD_PHASE2) ||
				g_strcmp0(field, CONNMAN_CONFIG_FIELD_KEYMGMT_TYPE) == 0) {
			DBG("field: %s, value: %s", field, value);

			if (value != NULL)
				g_key_file_set_string(keyfile, group_name, field, value);
		} else if (g_strcmp0(field, CONNMAN_CONFIG_FIELD_CA_CERT_FILE) == 0 ||
				g_strcmp0(field, CONNMAN_CONFIG_FIELD_CLIENT_CERT_FILE) == 0 ||
				g_strcmp0(field, CONNMAN_CONFIG_FIELD_PVT_KEY_FILE) == 0 ||
				g_strcmp0(field, CONNMAN_CONFIG_FIELD_PVT_KEY_PASSPHRASE) == 0) {
			if (value != NULL) {
				cert_file = strrchr(value, '/');
				if (cert_file == NULL) {
					ERR("Failed to get cert file: %s", value);
					goto out;
				}

				cert_file++;
				DBG("field: %s, value: %s", field, cert_file);

				dirname = g_strdup_printf("%s/%s",
						WIFI_CERT_STORAGEDIR, encoded_ssid);
				if (dirname == NULL) {
					ERR("Failed to create dirname");
					goto out;
				}
				if (g_file_test(dirname, G_FILE_TEST_IS_DIR) != TRUE) {
					if (mkdir(dirname, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP |
							S_IXGRP | S_IROTH | S_IXOTH) < 0) {
						if (errno != EEXIST) {
							g_free(dirname);
							goto out;
						}
					}
				}
				g_free(dirname);

				cert_path = g_strdup_printf("%s/%s/%s",
						WIFI_CERT_STORAGEDIR, encoded_ssid, cert_file);
				if (cert_path == NULL) {
					ERR("Failed to create cert path");
					goto out;
				}
				if (__netconfig_copy_config(value, cert_path) != TRUE) {
					ERR("Failed to read cert file %s", value);
					g_free(cert_path);
					goto out;
				}

				g_key_file_set_string(keyfile, group_name, field, cert_path);
				g_free(cert_path);
			}
		} else {
			DBG("field: %s, value: %s", field, value);

			if (value != NULL)
				g_key_file_set_string(keyfile, group_name, field, value);
		}
	}

	err = __config_save((const char *)encoded_ssid, keyfile);
	if (err < 0)
		ERR("Failed to create configuration %s[%d]", encoded_ssid, err);
	else {
		DBG("Successfully created %s", encoded_ssid);
		updated = TRUE;
	}

out:
	if (keyfile)
		g_key_file_free(keyfile);

	g_variant_iter_free(iter);

	if (field)
		g_free(field);

	if (value)
		g_free(value);

	g_free(group_name);
	g_free(encoded_ssid);

	return updated;
}

static gboolean _delete_configuration(const gchar *profile)
{
	gboolean ret = FALSE;
	gchar *config_id = NULL;

	ret = wifi_config_get_config_id(profile, &config_id);
	if (ret != TRUE) {
		ERR("Fail to get config_id from [%s]", profile);
		return ret;
	}
	ERR("get config_id [%s] from [%s]", config_id, profile);

	ret = wifi_config_remove_configuration(config_id);
	if (ret != TRUE) {
		ERR("Fail to wifi_config_remove_configuration [%s]", config_id);
	}

	if (config_id != NULL) {
		g_free(config_id);
	}

	return ret;
}

static gboolean __netconfig_delete_config(const char *profile)
{
	char *wifi_ident = NULL;
	char *essid = NULL;
	char *mode = NULL;
	char *ssid = NULL;
	int ssid_len = 0;
	int err = 0;

	if (NULL == profile) {
		ERR("Invalid profile name");
		return FALSE;
	}

	if (_delete_configuration(profile) != TRUE) {
		ERR("Fail to delete configuration [%s]", profile);
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
	err = __config_delete((const char *)ssid);
	if (err < 0) {
		ERR("Failed to delete configuration %s[%d]", ssid, err);
		g_free(ssid);
		return FALSE;
	}

	DBG("Successfully deleted %s with length %d", ssid, ssid_len);

	g_free(ssid);
	return TRUE;
}

static void __netconfig_eap_state(
		wifi_service_state_e state, void *user_data);

static wifi_state_notifier netconfig_eap_notifier = {
		.wifi_state_changed = __netconfig_eap_state,
		.user_data = NULL,
};

static void __netconfig_eap_state(
		wifi_service_state_e state, void *user_data)
{
	const char *wifi_profile = (const char *)user_data;

	if (wifi_profile == NULL) {
		wifi_state_notifier_unregister(&netconfig_eap_notifier);
		return;
	}

	if (state != NETCONFIG_WIFI_CONNECTED && state != NETCONFIG_WIFI_FAILURE)
		return;

	if (state == NETCONFIG_WIFI_FAILURE)
		__netconfig_delete_config(wifi_profile);

	g_free(netconfig_eap_notifier.user_data);
	netconfig_eap_notifier.user_data = NULL;

	wifi_state_notifier_unregister(&netconfig_eap_notifier);
}

gboolean handle_create_eap_config(Wifi *wifi, GDBusMethodInvocation *context,
		const gchar *service, GVariant *fields)
{
	gboolean updated = FALSE;
	gboolean reply = FALSE;
	gboolean result = FALSE;

	g_return_val_if_fail(wifi != NULL, FALSE);

	DBG("Set agent fields for %s", service);

	if (netconfig_is_wifi_profile(service) != TRUE) {
		netconfig_error_dbus_method_return(context, NETCONFIG_ERROR_WRONG_PROFILE, "InvalidService");
		return reply;
	}

	updated = __netconfig_create_config(fields);
	if (updated == TRUE) {
		wifi_complete_create_eap_config(wifi, context);

		if (g_strstr_len(service, strlen(service), "_hidden_") != NULL) {
			GVariantIter *iter;
			char *field, *value;
			const char *name = NULL;
			const char *identity = NULL;
			const char *passphrase = NULL;

			g_variant_get(fields, "a{ss}", &iter);

			while (g_variant_iter_loop(iter, "{ss}", &field, &value)) {
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

			g_variant_iter_free(iter);
		}

		result = netconfig_invoke_dbus_method_nonblock(CONNMAN_SERVICE,
				service, CONNMAN_SERVICE_INTERFACE, "Connect", NULL, NULL);

		if (netconfig_eap_notifier.user_data != NULL) {
			g_free(netconfig_eap_notifier.user_data);
			netconfig_eap_notifier.user_data = NULL;

			wifi_state_notifier_unregister(&netconfig_eap_notifier);
		}

		netconfig_eap_notifier.user_data = g_strdup(service);
		wifi_state_notifier_register(&netconfig_eap_notifier);
	} else {
		netconfig_error_dbus_method_return(context, NETCONFIG_ERROR_INVALID_PARAMETER, "InvalidArguments");
	}

	if (result != TRUE)
		ERR("Fail to connect %s", service);
	else
		reply = TRUE;

	return reply;
}

gboolean handle_delete_eap_config(Wifi *wifi, GDBusMethodInvocation *context,
		const gchar *profile)
{
	g_return_val_if_fail(wifi != NULL, FALSE);

	wifi_complete_delete_eap_config(wifi, context);

	gboolean ret = __netconfig_delete_config((const char *)profile);

	return ret;
}
