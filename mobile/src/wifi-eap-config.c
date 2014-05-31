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

#include <stdio.h>
#include <unistd.h>

#include "wifi-eap-config.h"
#include "log.h"
#include "wifi.h"

static char *__get_ssid(const char *name)
{
	char *buf = NULL;
	char buf_tmp[32] = {0,};
	int i = 0;
	int len = 0;

	if (NULL == name)
		return NULL;

	len = strlen(name);

	buf = g_try_malloc0(len * 2 + 1);
	if (buf == NULL)
		return NULL;

	for (i = 0; i < len; i++) {
		snprintf(buf_tmp, 3, "%02x", name[i]);
		strcat(buf, buf_tmp);
	}

	DBG("SSID - [%s]\n", buf);

	return buf;
}

static gboolean __config_save(GKeyFile *keyfile, char *file_name)
{
	gchar *data = NULL;
	gsize length = 0;
	FILE *file = NULL;
	int ret = TRUE;

	data = g_key_file_to_data(keyfile, &length, NULL);
	DBG("Data lenght-[%d]", length);

	file = fopen(file_name, "w");
	if (NULL == file) {
		DBG("fopen() fails!");
		ret = FALSE;
	} else {
		fputs(data, file);
		fclose(file);
		DBG("Wrote data successfully to [%s] file!", file_name);
	}

	g_free(data);

	return ret;
}

static gboolean __config_delete(const char *ssid)
{
	gchar *config_file = NULL;
	gboolean ret = FALSE;

	config_file = g_strdup_printf("%s/%s.config", CONNMAN_STORAGEDIR,
			ssid);
	if(config_file == NULL)
		return FALSE;

	if (g_file_test(config_file, G_FILE_TEST_EXISTS) == FALSE) {
		ret = TRUE;
	} else if (g_file_test(config_file, G_FILE_TEST_IS_REGULAR) == TRUE) {
		unlink(config_file);
		ret = TRUE;
	}

	g_free(config_file);

	return ret;
}

gboolean netconfig_iface_wifi_create_config(NetconfigWifi *wifi,
		GHashTable *fields, GError **error)
{
	DBG("netconfig_iface_wifi_create_config");
	g_return_val_if_fail(wifi != NULL, FALSE);

	gboolean ret = TRUE;
	GKeyFile *keyfile = NULL;
	GHashTableIter iter;
	gpointer field, value;
	gchar *file_name = NULL;
	gchar *ssid_hex = NULL;
	gchar *grp_name = NULL;

	g_hash_table_iter_init(&iter, fields);
	while (g_hash_table_iter_next(&iter, &field, &value)) {
		if (NULL != value) {
			if (!strcmp(field, CONNMAN_CONFIG_FIELD_NAME)) {
				ssid_hex = __get_ssid(value);
				break;
			} else if (!strcmp(field, CONNMAN_CONFIG_FIELD_SSID)) {
				ssid_hex = g_strdup_printf("%s",
						(gchar *)value);
				break;
			}
		}
	}

	if (NULL == ssid_hex) {
		DBG("Fail! Could not fetch the ssid");
		return FALSE;
	}

	/* Create unique service group name */
	grp_name = g_strdup_printf("service_%s", ssid_hex);
	if(NULL == grp_name) {
		DBG("Fail! Could not create the service group name");
		g_free(ssid_hex);
		return FALSE;
	}

	keyfile = g_key_file_new();
	if (NULL == keyfile) {
		DBG("g_key_file_new() fails!");
		g_free(grp_name);
		g_free(ssid_hex);
		return FALSE;
	}

	g_hash_table_iter_init(&iter, fields);
	while (g_hash_table_iter_next(&iter, &field, &value)) {
		DBG("Field - [%s] Value - [%s]", field, value);

		if (NULL != value)
			g_key_file_set_string(keyfile, grp_name, field, value);
	}

	file_name = g_strdup_printf("%s/%s.config", CONNMAN_STORAGEDIR,
			ssid_hex);
	if(NULL == file_name) {
		DBG("g_strdup_printf() fails. Could not save config!");
		g_key_file_free(keyfile);
		g_free(grp_name);
		g_free(ssid_hex);
		return FALSE;
	}

	ret = __config_save(keyfile, file_name);
	if (FALSE == ret)
		DBG("Could not save config!");
	else
		DBG("Saved config in [%s] successfully", file_name);

	g_key_file_free(keyfile);
	g_free(file_name);
	g_free(grp_name);
	g_free(ssid_hex);

	return ret;
}

gboolean netconfig_iface_wifi_delete_config(NetconfigWifi *wifi,
		gchar *profile, GError **error)
{
	DBG("netconfig_iface_wifi_delete_config");
	g_return_val_if_fail(wifi != NULL, FALSE);

	gboolean ret = TRUE;
	char *str1 = NULL;
	char *str2 = NULL;
	char *str3 = NULL;
	char ssid[512] = "";
	int ssid_len = 0;

	str1 = strstr(profile, "wifi_");
	if (NULL != str1) {
		str2 = strchr(str1 + 5, '_');
		if (NULL != str2) {
			str3 = strchr(str2 + 1, '_');
			ssid_len = str3 - str2 - 1;
			strncpy(ssid, str2 + 1, ssid_len);
			DBG("ssid_len - [%d] SSID - [%s]", ssid_len, ssid);

			ret = __config_delete(ssid);
			if (TRUE == ret)
				DBG("Deleted the config file successfully");
			else
				DBG("Deletion of config file failed");
		} else {
			DBG("Fetching of SSID fails");
		}
	} else {
		DBG("Fetching of SSID fails");
	}

	return ret;
}
