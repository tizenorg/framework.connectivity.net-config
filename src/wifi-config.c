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

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <sys/stat.h>
#include <glib.h>
#include <unistd.h>

#include <vconf.h>

#include "log.h"
#include "util.h"
#include "neterror.h"
#include "wifi-config.h"

#define CONNMAN_STORAGE         "/var/lib/connman"

#define WIFI_SECURITY_NONE		"none"
#define WIFI_SECURITY_WEP		"wep"
#define WIFI_SECURITY_WPA_PSK	"psk"
#define WIFI_SECURITY_EAP		"ieee8021x"

#define WIFI_CONFIG_PREFIX      "wifi_"
#define MAC_ADDRESS_LENGTH		12
#define WIFI_PREFIX_LENGTH		MAC_ADDRESS_LENGTH + 6	// wifi_485a3f2f506a_
#define PROFILE_PREFIX_LENGTH	WIFI_PREFIX_LENGTH + 21	// /net/connman/service/wifi_485a3f2f506a_

struct wifi_eap_config {
	gchar *anonymous_identity;
	gchar *ca_cert;
	gchar *client_cert;
	gchar *private_key;
	gchar *identity;
	gchar *eap_type;
	gchar *eap_auth_type;
	gchar *subject_match;
};

struct wifi_config {
	gchar *name;
	gchar *ssid;
	gchar *passphrase;
	gchar *security_type;
	gboolean favorite;
	gboolean autoconnect;
	gchar *is_hidden;
	gchar *proxy_address;
	struct wifi_eap_config *eap_config;
	gchar *last_error;
};

static void __free_wifi_configuration(struct wifi_config *conf)
{
	if (conf == NULL)
		return;

	g_free(conf->name);
	g_free(conf->ssid);
	g_free(conf->passphrase);
	g_free(conf->security_type);
	g_free(conf->is_hidden);
	g_free(conf->proxy_address);
	if (conf->eap_config) {
		g_free(conf->eap_config->anonymous_identity);
		g_free(conf->eap_config->ca_cert);
		g_free(conf->eap_config->client_cert);
		g_free(conf->eap_config->private_key);
		g_free(conf->eap_config->identity);
		g_free(conf->eap_config->eap_type);
		g_free(conf->eap_config->eap_auth_type);
		g_free(conf->eap_config->subject_match);
		g_free(conf->eap_config);
	}
	g_free(conf);
}

static gboolean __get_mac_address(gchar **mac_address)
{
	gchar *tmp_mac = NULL;
	gchar *tmp = NULL;
	gchar mac[13] = { 0, };
	gint i = 0, j = 0;

	tmp_mac = vconf_get_str(VCONFKEY_WIFI_BSSID_ADDRESS);
	if (tmp_mac == NULL) {
		ERR("vconf_get_str(WIFI_BSSID_ADDRESS) Failed");
		*mac_address = NULL;
		return FALSE;
	}
	tmp = g_ascii_strdown(tmp_mac, (gssize)strlen(tmp_mac));
	g_free(tmp_mac);

	while (tmp[i]) {
		if (tmp[i] != ':') {
			mac[j++] = tmp[i];
		}
		i++;
	}
	mac[12] = '\0';
	*mac_address = g_strdup(mac);

	return TRUE;
}

static gboolean __get_group_name(const gchar *prefix, const gchar *config_id, gchar **group_name)
{
	gchar *mac_address = NULL;
	gchar *g_name = NULL;
	gboolean ret = FALSE;

	ret = __get_mac_address(&mac_address);
	if ((ret != TRUE) || (strlen(mac_address) == 0)) {
		ERR("Cannot get WIFI MAC address");
		return FALSE;
	}

	g_name = g_strdup_printf("%s%s_%s", prefix, mac_address, config_id);
	if (g_name == NULL) {
		g_free(mac_address);
		return FALSE;
	}

	*group_name = g_strdup(g_name);

	g_free(mac_address);
	g_free(g_name);

	return TRUE;
}

static gboolean __get_security_type(const gchar *config_id, gchar **type)
{
	if (g_str_has_suffix(config_id, WIFI_SECURITY_NONE) == TRUE) {
		*type = g_strdup(WIFI_SECURITY_NONE);
	} else if (g_str_has_suffix(config_id, WIFI_SECURITY_WEP) == TRUE) {
		*type = g_strdup(WIFI_SECURITY_WEP);
	} else if (g_str_has_suffix(config_id, WIFI_SECURITY_WPA_PSK) == TRUE) {
		*type = g_strdup(WIFI_SECURITY_WPA_PSK);
	} else if (g_str_has_suffix(config_id, WIFI_SECURITY_EAP) == TRUE) {
		*type = g_strdup(WIFI_SECURITY_EAP);
	} else {
		*type = NULL;
		return FALSE;
	}

	return TRUE;
}

static gboolean __get_config_id(const gchar *profile, gchar **config_id)
{
	*config_id = g_strdup(profile + PROFILE_PREFIX_LENGTH);
	if (*config_id == NULL) {
		ERR("OOM");
		return FALSE;
	}

	return TRUE;
}


static GKeyFile *__get_configuration_keyfile(const gchar *group_name)
{
	GKeyFile *keyfile = NULL;
	gchar *path;

	path = g_strdup_printf(CONNMAN_STORAGE "/%s/settings", group_name);

	keyfile = netconfig_keyfile_load(path);
	if (keyfile == NULL) {
		ERR("keyfile[%s] is NULL", path);
		g_free(path);
	}

	return keyfile;
}

static gboolean __remove_file(const gchar *pathname, const gchar *filename)
{
	gboolean ret = FALSE;
	gchar *path;

	path = g_strdup_printf("%s/%s", pathname, filename);
	if (g_file_test(path, G_FILE_TEST_EXISTS) == FALSE) {
		ret = TRUE;
	} else if (g_file_test(path, G_FILE_TEST_IS_REGULAR) == TRUE) {
		unlink(path);
		ret = TRUE;
	}

	g_free(path);
	return ret;
}

static gboolean __remove_configuration(const gchar *pathname)
{
	int ret = 0;

	if (__remove_file(pathname, "settings") != TRUE) {
		ERR("Cannot remove [%s/settings]", pathname);
		return FALSE;
	}
	if (__remove_file(pathname, "data") != TRUE) {
		ERR("Cannot remove [%s/data]", pathname);
		return FALSE;
	}

	ret = rmdir(pathname);
	if (ret == -1) {
		ERR("Cannot remove [%s]", pathname);
		return FALSE;
	}

	return TRUE;
}

static gboolean _load_configuration(const gchar *config_id, struct wifi_config *config)
{
	GKeyFile *keyfile;
	gchar *group_name;
	gboolean hidden = FALSE;
	gboolean ret = FALSE;

	ret = __get_group_name(WIFI_CONFIG_PREFIX, config_id, &group_name);
	if (ret != TRUE) {
		ERR("Fail to get_wifi_config_group_name");
		return FALSE;
	}

	keyfile = __get_configuration_keyfile(group_name);
	if (keyfile == NULL) {
		ERR("Fail to __get_configuration_keyfile[%s]", group_name);
		g_free(group_name);
		return FALSE;
	}

	config->name = g_key_file_get_string(keyfile, group_name, WIFI_CONFIG_NAME, NULL);
	ret = __get_security_type(config_id, &config->security_type);
	if (ret != TRUE) {
		ERR("Fail to _get_security_type");
		g_key_file_free(keyfile);
		g_free(group_name);
		return FALSE;
	}
	config->proxy_address = g_key_file_get_string(keyfile, group_name, WIFI_CONFIG_PROXY_SERVER, NULL);
	hidden = g_key_file_get_boolean(keyfile, group_name, WIFI_CONFIG_HIDDEN, NULL);
	if (hidden) {
		config->is_hidden = g_strdup("TRUE");
	} else {
		config->is_hidden = g_strdup("FALSE");
	}

	if (g_strcmp0(config->security_type, WIFI_SECURITY_EAP) == 0) {
		config->eap_config->anonymous_identity = g_key_file_get_string(keyfile, group_name, WIFI_CONFIG_EAP_ANONYMOUS_IDENTITY, NULL);
		config->eap_config->ca_cert = g_key_file_get_string(keyfile, group_name, WIFI_CONFIG_EAP_CACERT, NULL);
		config->eap_config->client_cert = g_key_file_get_string(keyfile, group_name, WIFI_CONFIG_EAP_CLIENTCERT, NULL);
		config->eap_config->private_key = g_key_file_get_string(keyfile, group_name, WIFI_CONFIG_EAP_PRIVATEKEY, NULL);
		config->eap_config->identity = g_key_file_get_string(keyfile, group_name, WIFI_CONFIG_EAP_IDENTITY, NULL);
		config->eap_config->eap_type = g_key_file_get_string(keyfile, group_name, WIFI_CONFIG_EAP_TYPE, NULL);
		config->eap_config->eap_auth_type = g_key_file_get_string(keyfile, group_name, WIFI_CONFIG_EAP_AUTH_TYPE, NULL);
		config->eap_config->subject_match = g_key_file_get_string(keyfile, group_name, WIFI_CONFIG_EAP_SUBJECT_MATCH, NULL);
	}

	config->last_error = g_key_file_get_string(keyfile, group_name, WIFI_CONFIG_FAILURE, NULL);

	g_key_file_free(keyfile);
	g_free(group_name);

	return TRUE;
}

static gboolean _save_configuration(const gchar *config_id, GKeyFile *keyfile)
{
	gchar *dir;
	gchar *path;
	gchar *group_name;
	gboolean ret = FALSE;

	ret = __get_group_name(WIFI_CONFIG_PREFIX, config_id, &group_name);
	if (ret != TRUE) {
		ERR("Fail to get_wifi_config_group_name");
		return FALSE;
	}

	dir = g_strdup_printf(CONNMAN_STORAGE "/%s", group_name);
	if (g_file_test(dir, G_FILE_TEST_IS_DIR) == TRUE) {
		if (__remove_configuration(dir) != TRUE) {
			ERR("[%s] is existed, but cannot remove", dir);
			g_free(group_name);
			g_free(dir);
			return FALSE;
		}
	}

	if (mkdir(dir, (S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH)) < 0) {
		ERR("Cannot mkdir %s", dir);
		g_free(group_name);
		g_free(dir);
		return FALSE;
	}

	path = g_strdup_printf(CONNMAN_STORAGE "/%s/settings", group_name);
	netconfig_keyfile_save(keyfile, path);
	g_free(group_name);
	g_free(dir);
	g_free(path);

	return TRUE;
}

static gboolean _remove_configuration(const gchar *config_id)
{
	gboolean ret = FALSE;
	gchar *dir;
	gchar *group_name;

	ret = __get_group_name(WIFI_CONFIG_PREFIX, config_id, &group_name);
	if (ret != TRUE) {
		ERR("Fail to get_wifi_config_group_name");
		return FALSE;
	}

	dir = g_strdup_printf(CONNMAN_STORAGE "/%s", group_name);
	if (g_file_test(dir, G_FILE_TEST_IS_DIR) == TRUE) {
		if (__remove_configuration(dir) != TRUE) {
			ERR("[%s] is existed, but cannot remove", dir);
			ret = FALSE;
		}
		INFO("Success to remove [%s]", dir);
		ret = TRUE;
	} else {
		ERR("[%s] is not existed", dir);
		ret = FALSE;
	}

	g_free(group_name);
	g_free(dir);

	return ret;
}


static gboolean _set_field(const gchar *config_id, const gchar *key, const gchar *value)
{
	gboolean ret = TRUE;
	GKeyFile *keyfile;
	gchar *group_name;

	ret = __get_group_name(WIFI_CONFIG_PREFIX, config_id, &group_name);
	if (ret != TRUE) {
		ERR("Fail to get_wifi_config_group_name");
		return FALSE;
	}
	DBG("group_name %s", group_name);

	keyfile = __get_configuration_keyfile(group_name);
	if (keyfile == NULL) {
		ERR("Fail to __get_configuration_keyfile");
		return FALSE;
	}

	if (g_strcmp0(key, WIFI_CONFIG_PROXY_METHOD) == 0) {
		g_key_file_set_string(keyfile, group_name, key, value);
	}else if (g_strcmp0(key, WIFI_CONFIG_PROXY_SERVER) == 0) {
		g_key_file_set_string(keyfile, group_name, key, value);
	} else if (g_strcmp0(key, WIFI_CONFIG_HIDDEN) == 0) {
		gboolean hidden = FALSE;
		if (g_strcmp0(value, "TRUE") == 0) {
			hidden = TRUE;
		}
		g_key_file_set_boolean(keyfile, group_name, key, hidden);
	} else if (g_strcmp0(key, WIFI_CONFIG_EAP_ANONYMOUS_IDENTITY) == 0) {
		g_key_file_set_string(keyfile, group_name, key, value);
	} else if (g_strcmp0(key, WIFI_CONFIG_EAP_CACERT) == 0) {
		g_key_file_set_string(keyfile, group_name, key, value);
	} else if (g_strcmp0(key, WIFI_CONFIG_EAP_CLIENTCERT) == 0) {
		g_key_file_set_string(keyfile, group_name, key, value);
	} else if (g_strcmp0(key, WIFI_CONFIG_EAP_PRIVATEKEY) == 0) {
		g_key_file_set_string(keyfile, group_name, key, value);
	} else if (g_strcmp0(key, WIFI_CONFIG_EAP_IDENTITY) == 0) {
		g_key_file_set_string(keyfile, group_name, key, value);
	} else if (g_strcmp0(key, WIFI_CONFIG_EAP_TYPE) == 0) {
		g_key_file_set_string(keyfile, group_name, key, value);
	} else if (g_strcmp0(key, WIFI_CONFIG_EAP_AUTH_TYPE) == 0) {
		g_key_file_set_string(keyfile, group_name, key, value);
	} else if (g_strcmp0(key, WIFI_CONFIG_EAP_SUBJECT_MATCH) == 0) {
		g_key_file_set_string(keyfile, group_name, key, value);
	} else {
		ERR("key[%s] is not supported", key);
		ret = FALSE;
	}

	_save_configuration(config_id, keyfile);

	g_key_file_free(keyfile);
	g_free(group_name);

	return ret;
}

static gboolean _get_field(const gchar *config_id, const gchar *key, gchar **value)
{
	GKeyFile *keyfile;
	gchar *group_name;
	gchar *val = NULL;
	gboolean hidden = FALSE;
	gboolean ret = FALSE;

	ret = __get_group_name(WIFI_CONFIG_PREFIX, config_id, &group_name);
	if (ret != TRUE) {
		ERR("Fail to get_wifi_config_group_name");
		return FALSE;
	}
	DBG("group_name %s", group_name);

	keyfile = __get_configuration_keyfile(group_name);
	if (keyfile == NULL) {
		ERR("Fail to __get_configuration_keyfile");
		return FALSE;
	}

	if (g_strcmp0(key, WIFI_CONFIG_NAME) == 0) {
		val = g_key_file_get_string(keyfile, group_name, WIFI_CONFIG_NAME, NULL);
	} else if (g_strcmp0(key, WIFI_CONFIG_PASSPHRASE) == 0) {
		val = g_key_file_get_string(keyfile, group_name, WIFI_CONFIG_PASSPHRASE, NULL);
	} else if (g_strcmp0(key, WIFI_CONFIG_PROXY_SERVER) == 0) {
		val = g_key_file_get_string(keyfile, group_name, WIFI_CONFIG_PROXY_SERVER, NULL);
	} else if (g_strcmp0(key, WIFI_CONFIG_HIDDEN) == 0) {
		hidden = g_key_file_get_boolean(keyfile, group_name, WIFI_CONFIG_HIDDEN, NULL);
		if (hidden) {
			val = g_strdup("TRUE");
		} else {
			val = g_strdup("FALSE");
		}
	} else if (g_strcmp0(key, WIFI_CONFIG_EAP_ANONYMOUS_IDENTITY) == 0) {
		val = g_key_file_get_string(keyfile, group_name, WIFI_CONFIG_EAP_ANONYMOUS_IDENTITY, NULL);
	} else if (g_strcmp0(key, WIFI_CONFIG_EAP_CACERT) == 0) {
		val = g_key_file_get_string(keyfile, group_name, WIFI_CONFIG_EAP_CACERT, NULL);
	} else if (g_strcmp0(key, WIFI_CONFIG_EAP_CLIENTCERT) == 0) {
		val = g_key_file_get_string(keyfile, group_name, WIFI_CONFIG_EAP_CLIENTCERT, NULL);
	} else if (g_strcmp0(key, WIFI_CONFIG_EAP_PRIVATEKEY) == 0) {
		val = g_key_file_get_string(keyfile, group_name, WIFI_CONFIG_EAP_PRIVATEKEY, NULL);
	} else if (g_strcmp0(key, WIFI_CONFIG_EAP_IDENTITY) == 0) {
		val = g_key_file_get_string(keyfile, group_name, WIFI_CONFIG_EAP_IDENTITY, NULL);
	} else if (g_strcmp0(key, WIFI_CONFIG_EAP_TYPE) == 0) {
		val = g_key_file_get_string(keyfile, group_name, WIFI_CONFIG_EAP_TYPE, NULL);
	} else if (g_strcmp0(key, WIFI_CONFIG_EAP_AUTH_TYPE) == 0) {
		val = g_key_file_get_string(keyfile, group_name, WIFI_CONFIG_EAP_AUTH_TYPE, NULL);
	} else if (g_strcmp0(key, WIFI_CONFIG_EAP_SUBJECT_MATCH) == 0) {
		val = g_key_file_get_string(keyfile, group_name, WIFI_CONFIG_EAP_SUBJECT_MATCH, NULL);
	} else if (g_strcmp0(key, WIFI_CONFIG_FAILURE) == 0) {
		val = g_key_file_get_string(keyfile, group_name, WIFI_CONFIG_FAILURE, NULL);
	} else {
		ERR("Invalid key[%s]", key);
		val = g_strdup("NOTSUPPORTED");
	}

	*value = g_strdup(val);
	g_free(val);

	g_key_file_free(keyfile);
	g_free(group_name);

	return TRUE;
}

static GSList *_get_list(void)
{
	GSList *list = NULL;
	struct dirent *d;
	DIR *dir;

	dir = opendir(CONNMAN_STORAGE);
	if (dir == NULL) {
		ERR("Cannot open dir %s", CONNMAN_STORAGE);
		return NULL;
	}

	while ((d = readdir(dir))) {
		if (g_strcmp0(d->d_name, ".") == 0 || g_strcmp0(d->d_name, "..") == 0 ||
				strncmp(d->d_name, WIFI_CONFIG_PREFIX, strlen(WIFI_CONFIG_PREFIX)) != 0) {
			continue;
		}
		gchar *config_id = g_strdup(d->d_name + WIFI_PREFIX_LENGTH);
		list = g_slist_append(list, g_strdup(config_id));
		g_free(config_id);
	}
	closedir(dir);

	return list;
}

gboolean wifi_config_get_config_id(const gchar *service_profile, gchar **config_id)
{
	gboolean ret = FALSE;
	gchar *val = NULL;

	if ((service_profile == NULL) || (config_id == NULL)) {
		ERR("Invalid parameter");
		return FALSE;
	}

	ret = __get_config_id(service_profile, &val);
	*config_id = g_strdup(val);
	g_free(val);

	return ret;
}

gboolean wifi_config_remove_configuration(const gchar *config_id)
{
	gboolean ret = FALSE;

	ret = _remove_configuration(config_id);

	return ret;
}

// dbus method
gboolean handle_get_config_ids(Wifi *wifi, GDBusMethodInvocation *context)
{
	guint i = 0;
	GSList *config_ids = NULL;
	guint length;
	gchar **result = NULL;

	g_return_val_if_fail(wifi != NULL, FALSE);

	config_ids = _get_list();
	if (config_ids == NULL) {
		netconfig_error_no_profile(context);
		ERR("Fail to get config list");
		return FALSE;
	}

	length = g_slist_length(config_ids);
	result = g_new0(gchar *, length + 1);
	for (i = 0; i < length; i++) {
		gchar *config_id = g_slist_nth_data(config_ids, i);
		result[i] = g_strdup(config_id);
	}

	config_ids = g_slist_nth(config_ids, 0);
	g_slist_free_full(config_ids, g_free);

	wifi_complete_get_config_ids(wifi, context, (const gchar * const*)result);
	return TRUE;
}

gboolean handle_load_configuration(Wifi *wifi, GDBusMethodInvocation *context,
		const gchar *config_id)
{
	gboolean ret = FALSE;
	GVariantBuilder *b = NULL;
	struct wifi_config *conf = NULL;

	g_return_val_if_fail(wifi != NULL, FALSE);

	conf = g_new0(struct wifi_config, 1);

	ret = _load_configuration(config_id, conf);
	if (ret != TRUE) {
		g_free(conf);
		ERR("Fail to _load_configuration");
		netconfig_error_no_profile(context);
		return FALSE;
	}

	b = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));
	g_variant_builder_add(b, "{sv}", WIFI_CONFIG_NAME, g_variant_new_string(conf->name));
	g_variant_builder_add(b, "{sv}", WIFI_CONFIG_SECURITY_TYPE, g_variant_new_string(conf->security_type));
	g_variant_builder_add(b, "{sv}", WIFI_CONFIG_HIDDEN, g_variant_new_string(conf->is_hidden));
	if (conf->proxy_address != NULL) {
		g_variant_builder_add(b, "{sv}", WIFI_CONFIG_PROXYADDRESS, g_variant_new_string(conf->proxy_address));
		g_free(conf->proxy_address);
	} else {
		g_variant_builder_add(b, "{sv}", WIFI_CONFIG_PROXYADDRESS, g_variant_new_string("NONE"));
	}
	if (conf->last_error != NULL) {
		g_variant_builder_add(b, "{sv}", WIFI_CONFIG_FAILURE, g_variant_new_string(conf->last_error));
		g_free(conf->last_error);
	} else {
		g_variant_builder_add(b, "{sv}", WIFI_CONFIG_FAILURE, g_variant_new_string("ERROR_NONE"));
	}

	g_free(conf->name);
	g_free(conf->security_type);
	g_free(conf->is_hidden);
	g_free(conf);

	wifi_complete_load_configuration(wifi, context, g_variant_builder_end(b));
	g_variant_builder_unref(b);
	return TRUE;
}

gboolean handle_save_configuration(Wifi *wifi, GDBusMethodInvocation *context,
		const gchar *config_id, GVariant *configuration)
{
	gboolean ret = FALSE;
	struct wifi_config *conf = NULL;
	GKeyFile *keyfile = NULL;
	GVariantIter *iter;
	GVariant *value;
	gchar *field;
	gchar *group_name = NULL;

	if ((wifi == NULL) || (config_id == NULL) || (configuration == NULL)) {
		ERR("Invalid parameter");
		netconfig_error_invalid_parameter(context);
		SLOG(LOG_INFO, "MDM_LOG_USER", "Object=wifi-profile, AccessType=Create, Result=Failed");
		return FALSE;
	}

	ERR("save_configuration [%s]", config_id);

	conf = g_new0(struct wifi_config, 1);

	g_variant_get(configuration, "a{sv}", &iter);
	while (g_variant_iter_loop(iter, "{sv}", &field, &value)) {
		if (g_strcmp0(field, WIFI_CONFIG_NAME) == 0) {
			if (g_variant_is_of_type(value, G_VARIANT_TYPE_STRING)) {
				conf->name = g_strdup(g_variant_get_string(value, NULL));
				ERR("name [%s]", conf->name);
			} else {
				conf->name = NULL;
			}
		} else if (g_strcmp0(field, WIFI_CONFIG_SSID) == 0) {
			if (g_variant_is_of_type(value, G_VARIANT_TYPE_STRING)) {
				conf->ssid = g_strdup(g_variant_get_string(value, NULL));
				ERR("ssid [%s]", conf->ssid);
			} else {
				conf->ssid = NULL;
			}
		} else if (g_strcmp0(field, WIFI_CONFIG_PASSPHRASE) == 0) {
			if (g_variant_is_of_type(value, G_VARIANT_TYPE_STRING)) {
				conf->passphrase = g_strdup(g_variant_get_string(value, NULL));
				ERR("passphrase []");
			} else {
				conf->passphrase = NULL;
			}
		} else if (g_strcmp0(field, WIFI_CONFIG_HIDDEN) == 0) {
			if (g_variant_is_of_type(value, G_VARIANT_TYPE_STRING)) {
				conf->is_hidden = g_strdup(g_variant_get_string(value, NULL));
				ERR("is_hidden [%s]", conf->is_hidden);
			} else {
				conf->is_hidden = NULL;
			}
		} else if (g_strcmp0(field, WIFI_CONFIG_PROXYADDRESS) == 0) {
			if (g_variant_is_of_type(value, G_VARIANT_TYPE_STRING)) {
				conf->proxy_address = g_strdup(g_variant_get_string(value, NULL));
				ERR("proxy_address [%s]", conf->proxy_address);
			} else {
				conf->proxy_address = NULL;
			}
		}
	}
	conf->favorite = TRUE;
	conf->autoconnect = TRUE;

	ret = __get_group_name(WIFI_CONFIG_PREFIX, config_id, &group_name);
	if (ret != TRUE) {
		ERR("Fail to get_wifi_config_group_name");
		return FALSE;
	}

	keyfile = g_key_file_new();
	g_key_file_set_string(keyfile, group_name, WIFI_CONFIG_NAME, conf->name);
	g_key_file_set_string(keyfile, group_name, WIFI_CONFIG_SSID, conf->ssid);

	if (conf->passphrase != NULL)
		g_key_file_set_string(keyfile, group_name, WIFI_CONFIG_PASSPHRASE, conf->passphrase);

	g_key_file_set_boolean(keyfile, group_name, WIFI_CONFIG_FAVORITE, conf->favorite);
	g_key_file_set_boolean(keyfile, group_name, WIFI_CONFIG_AUTOCONNECT, conf->autoconnect);

	// Optional field
	if (conf->proxy_address != NULL) {
		g_key_file_set_string(keyfile, group_name, WIFI_CONFIG_PROXY_METHOD, "manual");
		g_key_file_set_string(keyfile, group_name, WIFI_CONFIG_PROXY_SERVER, conf->proxy_address);
	}

	if (conf->is_hidden != NULL) {
		gboolean hidden = FALSE;
		if (g_strcmp0(conf->is_hidden, "TRUE") == 0) {
			hidden = TRUE;
		}
		g_key_file_set_boolean(keyfile, group_name, WIFI_CONFIG_HIDDEN, hidden);
	}

	ret = _save_configuration(config_id, keyfile);
	if (ret == TRUE) {
		SLOG(LOG_INFO, "MDM_LOG_USER", "Object=wifi-profile, AccessType=Create, Result=Succeed");
		wifi_complete_save_configuration(wifi, context);
	} else {
		SLOG(LOG_INFO, "MDM_LOG_USER", "Object=wifi-profile, AccessType=Create, Result=Failed");
		netconfig_error_dbus_method_return(context, NETCONFIG_ERROR_INTERNAL, "FailSaveConfiguration");
	}

	g_key_file_free(keyfile);
	g_free(conf->name);
	g_free(conf->ssid);
	g_free(conf->passphrase);
	g_free(conf->is_hidden);
	g_free(conf->proxy_address);
	g_free(conf);

	g_variant_iter_free(iter);

	return ret;
}

gboolean handle_load_eap_configuration(Wifi *wifi, GDBusMethodInvocation *context,
		const gchar *config_id)
{
	gboolean ret = FALSE;
	GVariantBuilder *b = NULL;
	struct wifi_config *conf = NULL;

	g_return_val_if_fail(wifi != NULL, FALSE);

	conf = g_new0(struct wifi_config, 1);
	conf->eap_config = g_new0(struct wifi_eap_config, 1);

	ret = _load_configuration(config_id, conf);
	if (ret != TRUE) {
		g_free(conf->eap_config);
		g_free(conf);
		ERR("Fail to _load_configuration");
		netconfig_error_no_profile(context);
		return FALSE;
	}

	b = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));
	g_variant_builder_add(b, "{sv}", WIFI_CONFIG_NAME, g_variant_new_string(conf->name));
	g_variant_builder_add(b, "{sv}", WIFI_CONFIG_SECURITY_TYPE, g_variant_new_string(conf->security_type));
	g_variant_builder_add(b, "{sv}", WIFI_CONFIG_HIDDEN, g_variant_new_string(conf->is_hidden));
	if (conf->proxy_address != NULL) {
		g_variant_builder_add(b, "{sv}", WIFI_CONFIG_PROXYADDRESS, g_variant_new_string(conf->proxy_address));
		g_free(conf->proxy_address);
	} else {
		g_variant_builder_add(b, "{sv}", WIFI_CONFIG_PROXYADDRESS, g_variant_new_string("NONE"));
	}
	if (conf->last_error != NULL) {
		g_variant_builder_add(b, "{sv}", WIFI_CONFIG_FAILURE, g_variant_new_string(conf->last_error));
		g_free(conf->last_error);
	} else {
		g_variant_builder_add(b, "{sv}", WIFI_CONFIG_FAILURE, g_variant_new_string("ERROR_NONE"));
	}
	if (conf->eap_config != NULL) {
		if (conf->eap_config->anonymous_identity != NULL) {
			g_variant_builder_add(b, "{sv}", WIFI_CONFIG_EAP_ANONYMOUS_IDENTITY, g_variant_new_string(conf->eap_config->anonymous_identity));
		} else {
			g_variant_builder_add(b, "{sv}", WIFI_CONFIG_EAP_ANONYMOUS_IDENTITY, g_variant_new_string("NONE"));
		}
		if (conf->eap_config->ca_cert != NULL) {
			g_variant_builder_add(b, "{sv}", WIFI_CONFIG_EAP_CACERT, g_variant_new_string(conf->eap_config->ca_cert));
		} else {
			g_variant_builder_add(b, "{sv}", WIFI_CONFIG_EAP_CACERT, g_variant_new_string("NONE"));
		}
		if (conf->eap_config->client_cert != NULL) {
			g_variant_builder_add(b, "{sv}", WIFI_CONFIG_EAP_CLIENTCERT, g_variant_new_string(conf->eap_config->client_cert));
		} else {
			g_variant_builder_add(b, "{sv}", WIFI_CONFIG_EAP_CLIENTCERT, g_variant_new_string("NONE"));
		}
		if (conf->eap_config->private_key != NULL) {
			g_variant_builder_add(b, "{sv}", WIFI_CONFIG_EAP_PRIVATEKEY, g_variant_new_string(conf->eap_config->private_key));
		} else {
			g_variant_builder_add(b, "{sv}", WIFI_CONFIG_EAP_PRIVATEKEY, g_variant_new_string("NONE"));
		}
		if (conf->eap_config->identity != NULL) {
			g_variant_builder_add(b, "{sv}", WIFI_CONFIG_EAP_IDENTITY, g_variant_new_string(conf->eap_config->identity));
		} else {
			g_variant_builder_add(b, "{sv}", WIFI_CONFIG_EAP_IDENTITY, g_variant_new_string("NONE"));
		}
		if (conf->eap_config->eap_type != NULL) {
			g_variant_builder_add(b, "{sv}", WIFI_CONFIG_EAP_TYPE, g_variant_new_string(conf->eap_config->eap_type));
		} else {
			g_variant_builder_add(b, "{sv}", WIFI_CONFIG_EAP_TYPE, g_variant_new_string("NONE"));
		}
		if (conf->eap_config->eap_auth_type != NULL) {
			g_variant_builder_add(b, "{sv}", WIFI_CONFIG_EAP_AUTH_TYPE, g_variant_new_string(conf->eap_config->eap_auth_type));
		} else {
			g_variant_builder_add(b, "{sv}", WIFI_CONFIG_EAP_AUTH_TYPE, g_variant_new_string("NONE"));
		}
		if (conf->eap_config->subject_match != NULL) {
			g_variant_builder_add(b, "{sv}", WIFI_CONFIG_EAP_SUBJECT_MATCH, g_variant_new_string(conf->eap_config->subject_match));
		} else {
			g_variant_builder_add(b, "{sv}", WIFI_CONFIG_EAP_SUBJECT_MATCH, g_variant_new_string("NONE"));
		}
	}

	__free_wifi_configuration(conf);

	wifi_complete_load_eap_configuration(wifi, context, g_variant_builder_end(b));
	g_variant_builder_unref(b);
	return TRUE;
}

gboolean handle_save_eap_configuration(Wifi *wifi, GDBusMethodInvocation *context,
		const gchar *config_id, GVariant *configuration)
{
	gboolean ret = FALSE;
	struct wifi_config *conf = NULL;
	GKeyFile *keyfile = NULL;
	GVariantIter *iter;
	GVariant *value;
	gchar *field;
	gchar *group_name = NULL;

	if ((wifi == NULL) || (config_id == NULL) || (configuration == NULL)) {
		ERR("Invalid parameter");
		netconfig_error_invalid_parameter(context);
		SLOG(LOG_INFO, "MDM_LOG_USER", "Object=wifi-profile, AccessType=Create, Result=Failed");
		return FALSE;
	}

	INFO("save [%s]", config_id);

	conf = g_new0(struct wifi_config, 1);
	conf->eap_config = g_new0(struct wifi_eap_config, 1);

	g_variant_get(configuration, "a{sv}", &iter);
	while (g_variant_iter_loop(iter, "{sv}", &field, &value)) {
		if (g_strcmp0(field, WIFI_CONFIG_NAME) == 0) {
			if (g_variant_is_of_type(value, G_VARIANT_TYPE_STRING)) {
				conf->name = g_strdup(g_variant_get_string(value, NULL));
				ERR("name [%s]", conf->name);
			} else {
				conf->name = NULL;
			}
		} else if (g_strcmp0(field, WIFI_CONFIG_SSID) == 0) {
			if (g_variant_is_of_type(value, G_VARIANT_TYPE_STRING)) {
				conf->ssid = g_strdup(g_variant_get_string(value, NULL));
				ERR("ssid [%s]", conf->ssid);
			} else {
				conf->ssid = NULL;
			}
		} else if (g_strcmp0(field, WIFI_CONFIG_PASSPHRASE) == 0) {
			if (g_variant_is_of_type(value, G_VARIANT_TYPE_STRING)) {
				conf->passphrase = g_strdup(g_variant_get_string(value, NULL));
				ERR("passphrase [%s]", conf->passphrase);
			} else {
				conf->passphrase = NULL;
			}
		} else if (g_strcmp0(field, WIFI_CONFIG_HIDDEN) == 0) {
			if (g_variant_is_of_type(value, G_VARIANT_TYPE_STRING)) {
				conf->is_hidden = g_strdup(g_variant_get_string(value, NULL));
				ERR("is_hidden [%s]", conf->is_hidden);
			} else {
				conf->is_hidden = NULL;
			}
		} else if (g_strcmp0(field, WIFI_CONFIG_PROXYADDRESS) == 0) {
			if (g_variant_is_of_type(value, G_VARIANT_TYPE_STRING)) {
				conf->proxy_address = g_strdup(g_variant_get_string(value, NULL));
				ERR("proxy_address [%s]", conf->proxy_address);
			} else {
				conf->proxy_address = NULL;
			}
		} else if (g_strcmp0(field, WIFI_CONFIG_EAP_ANONYMOUS_IDENTITY) == 0) {
			if (g_variant_is_of_type(value, G_VARIANT_TYPE_STRING)) {
				conf->eap_config->anonymous_identity = g_strdup(g_variant_get_string(value, NULL));
				ERR("anonymous_identity [%s]", conf->eap_config->anonymous_identity);
			} else {
				conf->eap_config->anonymous_identity = NULL;
			}
		} else if (g_strcmp0(field, WIFI_CONFIG_EAP_CACERT) == 0) {
			if (g_variant_is_of_type(value, G_VARIANT_TYPE_STRING)) {
				conf->eap_config->ca_cert = g_strdup(g_variant_get_string(value, NULL));
				ERR("ca_cert [%s]", conf->eap_config->ca_cert);
			} else {
				conf->eap_config->ca_cert = NULL;
			}
		} else if (g_strcmp0(field, WIFI_CONFIG_EAP_CLIENTCERT) == 0) {
			if (g_variant_is_of_type(value, G_VARIANT_TYPE_STRING)) {
				conf->eap_config->client_cert = g_strdup(g_variant_get_string(value, NULL));
				ERR("client_cert [%s]", conf->eap_config->client_cert);
			} else {
				conf->eap_config->client_cert = NULL;
			}
		} else if (g_strcmp0(field, WIFI_CONFIG_EAP_PRIVATEKEY) == 0) {
			if (g_variant_is_of_type(value, G_VARIANT_TYPE_STRING)) {
				conf->eap_config->private_key = g_strdup(g_variant_get_string(value, NULL));
				ERR("private_key [%s]", conf->eap_config->private_key);
			} else {
				conf->eap_config->private_key = NULL;
			}
		} else if (g_strcmp0(field, WIFI_CONFIG_EAP_IDENTITY) == 0) {
			if (g_variant_is_of_type(value, G_VARIANT_TYPE_STRING)) {
				conf->eap_config->identity = g_strdup(g_variant_get_string(value, NULL));
				ERR("identity [%s]", conf->eap_config->identity);
			} else {
				conf->eap_config->identity = NULL;
			}
		} else if (g_strcmp0(field, WIFI_CONFIG_EAP_TYPE) == 0) {
			if (g_variant_is_of_type(value, G_VARIANT_TYPE_STRING)) {
				conf->eap_config->eap_type = g_strdup(g_variant_get_string(value, NULL));
				ERR("eap_type [%s]", conf->eap_config->eap_type);
			} else {
				conf->eap_config->eap_type = NULL;
			}
		} else if (g_strcmp0(field, WIFI_CONFIG_EAP_AUTH_TYPE) == 0) {
			if (g_variant_is_of_type(value, G_VARIANT_TYPE_STRING)) {
				conf->eap_config->eap_auth_type = g_strdup(g_variant_get_string(value, NULL));
				ERR("eap_auth_type [%s]", conf->eap_config->eap_auth_type);
			} else {
				conf->eap_config->eap_auth_type = NULL;
			}
		} else if (g_strcmp0(field, WIFI_CONFIG_EAP_SUBJECT_MATCH) == 0) {
			if (g_variant_is_of_type(value, G_VARIANT_TYPE_STRING)) {
				conf->eap_config->subject_match = g_strdup(g_variant_get_string(value, NULL));
				ERR("subject_match [%s]", conf->eap_config->subject_match);
			} else {
				conf->eap_config->subject_match = NULL;
			}
		}
	}
	conf->favorite = TRUE;
	conf->autoconnect = TRUE;

	ret = __get_group_name(WIFI_CONFIG_PREFIX, config_id, &group_name);
	if (ret != TRUE) {
		__free_wifi_configuration(conf);
		ERR("Fail to get_wifi_config_group_name");
		return FALSE;
	}

	keyfile = g_key_file_new();
	g_key_file_set_string(keyfile, group_name, WIFI_CONFIG_NAME, conf->name);
	g_key_file_set_string(keyfile, group_name, WIFI_CONFIG_SSID, conf->ssid);

	if (conf->passphrase != NULL)
		g_key_file_set_string(keyfile, group_name, WIFI_CONFIG_PASSPHRASE, conf->passphrase);

	g_key_file_set_boolean(keyfile, group_name, WIFI_CONFIG_FAVORITE, conf->favorite);
	g_key_file_set_boolean(keyfile, group_name, WIFI_CONFIG_AUTOCONNECT, conf->autoconnect);

	// Optional field
	if (conf->proxy_address != NULL) {
		g_key_file_set_string(keyfile, group_name, WIFI_CONFIG_PROXY_METHOD, "manual");
		g_key_file_set_string(keyfile, group_name, WIFI_CONFIG_PROXY_SERVER, conf->proxy_address);
	}

	if (conf->is_hidden != NULL) {
		gboolean hidden = FALSE;
		if (g_strcmp0(conf->is_hidden, "TRUE") == 0) {
			hidden = TRUE;
		}
		g_key_file_set_boolean(keyfile, group_name, WIFI_CONFIG_HIDDEN, hidden);
	}

	ret = _save_configuration(config_id, keyfile);
	if (ret == TRUE) {
		SLOG(LOG_INFO, "MDM_LOG_USER", "Object=wifi-profile, AccessType=Create, Result=Succeed");
		wifi_complete_save_eap_configuration(wifi, context);
	} else {
		SLOG(LOG_INFO, "MDM_LOG_USER", "Object=wifi-profile, AccessType=Create, Result=Failed");
		netconfig_error_dbus_method_return(context, NETCONFIG_ERROR_INTERNAL, "FailSaveEapConfiguration");
	}

	g_key_file_free(keyfile);
	__free_wifi_configuration(conf);

	g_variant_iter_free(iter);

	return ret;
}

gboolean handle_remove_configuration(Wifi *wifi, GDBusMethodInvocation *context, const gchar *config_id)
{
	gboolean ret = FALSE;

	if ((wifi == NULL) || (config_id == NULL)) {
		ERR("Invalid parameter");
		netconfig_error_invalid_parameter(context);
		return FALSE;
	}

	ret = _remove_configuration(config_id);
	if (ret != TRUE) {
		// no configuration or error
		ERR("No [%s] configuration", config_id);
		netconfig_error_no_profile(context);
		return FALSE;
	}

	wifi_complete_remove_configuration(wifi, context);
	return ret;
}

// config field key / value
/*
 * [wifi_macaddress_config_id]
 * Name=name (mandatory)
 * SSID=SSID (mandatory)
 * Frequency=2462 (X)
 * Favorite=true (X)
 * AutoConnect=true (Default true)
 * Modified=2015-03-20 (X)
 * IPv4.method=manual (O)
 * IPv4.DHCP.LastAddress=192.0.0.1 (X)
 * IPv6.method=auto (X)
 * IPv6.privacy=disabled (X)
 * IPv4.netmask_prefixlen=24 (X)
 * IPv4.local_address=192.0.0.1 (O)
 * IPv4.gateway=192.0.0.1 (O ? X ?)
 * Nameservers=192.168.43.22; (O)
 * Proxy.Method=manual (O)
 * Proxy.Servers=trst.com:8888; (O)
 */
gboolean handle_set_config_field(Wifi *wifi, GDBusMethodInvocation *context,
		const gchar *config_id, const gchar *key, const gchar *value)
{
	gboolean ret = FALSE;
	gchar *keyfile_key = NULL;

	g_return_val_if_fail(wifi != NULL, FALSE);
	g_return_val_if_fail(config_id != NULL, FALSE);
	g_return_val_if_fail(key != NULL, FALSE);

	DBG("Key[%s] Value[%d]", key, value);

	if (g_strcmp0(key, WIFI_CONFIG_PROXYADDRESS) == 0) {
		ret = _set_field(config_id, WIFI_CONFIG_PROXY_METHOD, "manual");
		if (!ret) {
			ERR("Fail to [%s]set_wifi_config_field(%s/manual)", config_id, WIFI_CONFIG_PROXY_METHOD);
			netconfig_error_invalid_parameter(context);
			return FALSE;
		}
		keyfile_key = g_strdup_printf("%s", WIFI_CONFIG_PROXY_SERVER);
	} else if (g_strcmp0(key, WIFI_CONFIG_HIDDEN) == 0) {
		keyfile_key = g_strdup_printf("%s", WIFI_CONFIG_HIDDEN);
	} else if (g_strcmp0(key, WIFI_CONFIG_EAP_ANONYMOUS_IDENTITY) == 0) {
		keyfile_key = g_strdup_printf("%s", WIFI_CONFIG_EAP_ANONYMOUS_IDENTITY);
	} else if (g_strcmp0(key, WIFI_CONFIG_EAP_CACERT) == 0) {
		keyfile_key = g_strdup_printf("%s", WIFI_CONFIG_EAP_CACERT);
	} else if (g_strcmp0(key, WIFI_CONFIG_EAP_CLIENTCERT) == 0) {
		keyfile_key = g_strdup_printf("%s", WIFI_CONFIG_EAP_CLIENTCERT);
	} else if (g_strcmp0(key, WIFI_CONFIG_EAP_PRIVATEKEY) == 0) {
		keyfile_key = g_strdup_printf("%s", WIFI_CONFIG_EAP_PRIVATEKEY);
	} else if (g_strcmp0(key, WIFI_CONFIG_EAP_IDENTITY) == 0) {
		keyfile_key = g_strdup_printf("%s", WIFI_CONFIG_EAP_IDENTITY);
	} else if (g_strcmp0(key, WIFI_CONFIG_EAP_TYPE) == 0) {
		keyfile_key = g_strdup_printf("%s", WIFI_CONFIG_EAP_TYPE);
	} else if (g_strcmp0(key, WIFI_CONFIG_EAP_AUTH_TYPE) == 0) {
		keyfile_key = g_strdup_printf("%s", WIFI_CONFIG_EAP_AUTH_TYPE);
	} else if (g_strcmp0(key, WIFI_CONFIG_EAP_SUBJECT_MATCH) == 0) {
		keyfile_key = g_strdup_printf("%s", WIFI_CONFIG_EAP_SUBJECT_MATCH);
	} else {
		ERR("Not supported key[%s]", key);
		netconfig_error_invalid_parameter(context);
		return FALSE;
	}

	ret = _set_field(config_id, keyfile_key, (const gchar *)value);
	if (!ret) {
		ERR("Fail to [%s]set_wifi_config_field(%s/%s)", config_id, key, value);
		ret = FALSE;
	}

	if (keyfile_key != NULL)
		g_free(keyfile_key);

	wifi_complete_set_config_field(wifi,context);
	return ret;
}

gboolean handle_get_config_passphrase(Wifi *wifi, GDBusMethodInvocation *context, const gchar *config_id)
{
	gboolean ret = FALSE;
	gchar *passphrase = NULL;

	if ((wifi == NULL) || (config_id == NULL)) {
		ERR("Invalid parameter");
		netconfig_error_invalid_parameter(context);
		return FALSE;
	}

	ret = _get_field(config_id, WIFI_CONFIG_PASSPHRASE, &passphrase);
	if (!ret) {
		ERR("Fail to [%s] _get_field(%s)", config_id, WIFI_CONFIG_PASSPHRASE);
		netconfig_error_dbus_method_return(context, NETCONFIG_ERROR_INTERNAL, "OperationFailed");
		return FALSE;
	}

	wifi_complete_get_config_passphrase(wifi, context, passphrase);
	g_free(passphrase);

	return ret;
}
