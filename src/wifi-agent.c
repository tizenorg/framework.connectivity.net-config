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

#include "wifi-agent.h"
#include "log.h"
#include "wifi.h"
#include "netdbus.h"

#define NETCONFIG_AGENT_FIELD_PASSPHRASE		"Passphrase"
#define NETCONFIG_AGENT_FIELD_WPS				"WPS"
#define NETCONFIG_AGENT_FIELD_WPS_PBC			"WPS_PBC"
#define NETCONFIG_AGENT_FIELD_WPS_PIN			"WPS_PIN"

struct netconfig_wifi_agent {
	char *passphrase;
	char *wps_pin;
	gboolean wps_pbc;
};

static struct netconfig_wifi_agent agent;

static void __netconfig_agent_clear_fields(void)
{
	DBG("__netconfig_agent_clear_fields");

	g_free(agent.passphrase);
	g_free(agent.wps_pin);

	agent.passphrase = NULL;
	agent.wps_pin = NULL;
	agent.wps_pbc = FALSE;
}

gboolean netconfig_agent_register(void)
{
	DBG("netconfig_agent_register");

	DBusMessage *reply = NULL;
	char param1[64] = "";
	char *param_array[] = {NULL, NULL};

	snprintf(param1, 64, "objpath:%s", NETCONFIG_WIFI_PATH);
	param_array[0] = param1;

	reply = netconfig_invoke_dbus_method(CONNMAN_SERVICE,
			CONNMAN_MANAGER_PATH, CONNMAN_MANAGER_INTERFACE,
			"RegisterAgent", param_array);

	if (reply == NULL) {
		ERR("Error! Request failed");
		return FALSE;
	}

	dbus_message_unref(reply);

	return TRUE;
}

gboolean netconfig_agent_unregister(void)
{
	DBG("netconfig_agent_unregister");

	DBusMessage *reply = NULL;
	char param1[64] = "";
	char *param_array[] = {NULL, NULL};

	snprintf(param1, 64, "objpath:%s", NETCONFIG_WIFI_PATH);
	param_array[0] = param1;

	reply = netconfig_invoke_dbus_method(CONNMAN_SERVICE,
			CONNMAN_MANAGER_PATH, CONNMAN_MANAGER_INTERFACE,
			"UnregisterAgent", param_array);

	if (reply == NULL) {
		ERR("Error! Request failed");
		return FALSE;
	}

	dbus_message_unref(reply);

	/* Clearing the agent fields */
	__netconfig_agent_clear_fields();

	return TRUE;
}

gboolean netconfig_iface_wifi_set_field(NetconfigWifi *wifi,
		GHashTable *fields, GError **error)
{
	GHashTableIter iter;
	gpointer field, value;

	DBG("Set agent fields");

	g_return_val_if_fail(wifi != NULL, FALSE);

	__netconfig_agent_clear_fields();

	g_hash_table_iter_init(&iter, fields);

	while (g_hash_table_iter_next(&iter, &field, &value)) {
		DBG("Field - [%s]", field);
		if (g_strcmp0(field, NETCONFIG_AGENT_FIELD_PASSPHRASE) == 0) {
			g_free(agent.passphrase);
			agent.passphrase = g_strdup(value);

			DBG("Field [%s] - []", field);
		} else if (g_strcmp0(field, NETCONFIG_AGENT_FIELD_WPS_PBC) == 0) {
			agent.wps_pbc = FALSE;
			if (g_strcmp0(value, "enable") == 0)
				agent.wps_pbc = TRUE;

			DBG("Field [%s] - [%d]", field, agent.wps_pbc);
		} else if (g_strcmp0(field, NETCONFIG_AGENT_FIELD_WPS_PIN) == 0) {
			g_free(agent.wps_pin);
			agent.wps_pbc = FALSE;
			agent.wps_pin = g_strdup(value);

			DBG("Field [%s] - []", field);
		}
	}

	return TRUE;
}

gboolean netconfig_iface_wifi_request_input(NetconfigWifi *wifi,
		gchar *service, GHashTable *fields,
		DBusGMethodInvocation *context)
{
	GHashTableIter iter;
	gpointer field, value;
	GHashTable *out_table = NULL;
	GValue *ret_value = NULL;

	g_return_val_if_fail(wifi != NULL, FALSE);

	if (NULL == service)
		return FALSE;

	DBG("Agent fields requested for service: %s", service);

	out_table = g_hash_table_new_full(g_str_hash, g_str_equal, g_free, g_free);
	if (NULL == out_table)
		return FALSE;

	g_hash_table_iter_init(&iter, fields);

	while (g_hash_table_iter_next(&iter, &field, &value)) {
		if (g_strcmp0(field, NETCONFIG_AGENT_FIELD_PASSPHRASE) == 0 &&
				agent.passphrase != NULL) {
			ret_value = g_slice_new0(GValue);

			g_value_init(ret_value, G_TYPE_STRING);
			g_value_set_string(ret_value, agent.passphrase);
			g_hash_table_insert(out_table, g_strdup(field), ret_value);

			DBG("Setting [%s] - []", field);
		} else if (g_strcmp0(field, NETCONFIG_AGENT_FIELD_WPS) == 0 &&
				(agent.wps_pbc == TRUE || agent.wps_pin != NULL)) {
			ret_value = g_slice_new0(GValue);

			g_value_init(ret_value, G_TYPE_STRING);

			if (agent.wps_pbc == TRUE) {
				/* Sending empty string for WPS push button method */
				g_value_set_string(ret_value, "");

				DBG("Setting empty string for [%s]", field);
			} else if (agent.wps_pin != NULL) {
				g_value_set_string(ret_value, agent.wps_pin);

				DBG("Setting string [%s] - []", field);
			}

			g_hash_table_insert(out_table, g_strdup(field), ret_value);
		}
	}

	dbus_g_method_return(context, out_table);

	__netconfig_agent_clear_fields();

	return TRUE;
}
