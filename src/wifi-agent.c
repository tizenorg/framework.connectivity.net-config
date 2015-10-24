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

#include <app.h>
#include <stdio.h>
#include <vconf.h>
#include <stdlib.h>
#include <unistd.h>
#include <vconf-keys.h>

#include "log.h"
#include "util.h"
#include "wifi.h"
#include "netdbus.h"
#include "wifi-agent.h"
#include "wifi-state.h"
#include "wifi-eap-config.h"
#include "network-state.h"
#include "network-accessibility.h"

#define NETCONFIG_AGENT_FIELD_NAME				"Name"
#define NETCONFIG_AGENT_FIELD_SSID				"SSID"
#define NETCONFIG_AGENT_FIELD_IDENTITY			"Identity"
#define NETCONFIG_AGENT_FIELD_PASSPHRASE		"Passphrase"
#define NETCONFIG_AGENT_FIELD_WPS				"WPS"
#define NETCONFIG_AGENT_FIELD_WPS_PBC			"WPS_PBC"
#define NETCONFIG_AGENT_FIELD_WPS_PIN			"WPS_PIN"

#define NETCONFIG_AGENT_ERR_CONNECT_FAILED		"connect-failed"

struct netconfig_wifi_agent {
	GByteArray *ssid;
	char *name;
	char *identity;
	char *passphrase;
	char *wps_pin;
	gboolean wps_pbc;
};

static struct netconfig_wifi_agent agent;

static void __netconfig_agent_clear_fields(void)
{
	g_byte_array_free(agent.ssid, TRUE);
	g_free(agent.name);
	g_free(agent.identity);
	g_free(agent.passphrase);
	g_free(agent.wps_pin);

	agent.ssid = NULL;
	agent.name = NULL;
	agent.identity = NULL;
	agent.passphrase = NULL;
	agent.wps_pin = NULL;
	agent.wps_pbc = FALSE;
}

int connman_register_agent(void)
{
	GVariant *reply = NULL;
	GVariant *params = NULL;
	GError *error;
	GDBusConnection *connection = NULL;

	connection = netdbus_get_connection();
	if (connection == NULL) {
		ERR("GDBusconnection is NULL");
		return -1;
	}

	do {
		error = NULL;
		params = g_variant_new("(o)", NETCONFIG_WIFI_PATH);

		reply = g_dbus_connection_call_sync(
				connection,
				CONNMAN_SERVICE,
				CONNMAN_MANAGER_PATH,
				CONNMAN_MANAGER_INTERFACE,
				"RegisterAgent",
				params,
				NULL,
				G_DBUS_CALL_FLAGS_NONE,
				DBUS_REPLY_TIMEOUT,
				netdbus_get_cancellable(),
				&error);

		if (reply == NULL) {
	    	 if (error != NULL) {
	    		 if (g_strcmp0(error->message,
	    				 "GDBus.Error:net.connman.Error.AlreadyExists: Already exists") == 0) {
					break;
	    		 } else {
	    			 ERR("Fail to register agent [%d: %s]",
	    					 error->code, error->message);
	    		 }

	    		 g_error_free(error);
	    	 } else
	    		 ERR("Fail to register agent");
		} else
			g_variant_unref(reply);

		sleep(1);
	} while (TRUE);

	INFO("Registered to connman agent successfully");

	return 0;
}

int connman_unregister_agent(void)
{
	gboolean reply = FALSE;
	GVariant *param = NULL;
	const char *path = NETCONFIG_WIFI_PATH;

	param = g_variant_new("(o)", path);

	DBG("ConnMan agent unregister");

	reply = netconfig_invoke_dbus_method_nonblock(CONNMAN_SERVICE,
			CONNMAN_MANAGER_PATH, CONNMAN_MANAGER_INTERFACE,
			"UnregisterAgent", param, NULL);

	if (reply != TRUE)
		ERR("Fail to unregister agent");

	/* Clearing the agent fields */
	__netconfig_agent_clear_fields();

	return reply;
}

gboolean netconfig_wifi_set_agent_field_for_eap_network(
		const char *name, const char *identity, const char *passphrase)
{
	int name_len;

	if (name == NULL)
		return FALSE;

	__netconfig_agent_clear_fields();

	name_len = strlen(name);
	agent.ssid = g_byte_array_sized_new(name_len);
	agent.ssid->len = name_len;
	memcpy(agent.ssid->data, name, name_len);

	if (identity)
		agent.identity = g_strdup(identity);

	if (passphrase)
		agent.passphrase = g_strdup(passphrase);

	DBG("Successfully configured for EAP network");

	return TRUE;
}

gboolean handle_set_field(NetConnmanAgent *connman_agent,
		GDBusMethodInvocation *context, const gchar *service, GVariant *fields)
{
	GError *error = NULL;
	GVariantIter *iter;
	gpointer field;
	GVariant *value;
	gboolean updated = FALSE;
	gboolean reply = FALSE;

	g_return_val_if_fail(connman_agent != NULL, FALSE);

	DBG("Set agent fields for %s", service);

	if (netconfig_is_wifi_profile(service) != TRUE) {
		error = g_error_new(G_DBUS_ERROR,
				G_DBUS_ERROR_AUTH_FAILED,
				CONNMAN_ERROR_INTERFACE ".InvalidService");

		g_dbus_method_invocation_return_gerror(context, error);
		g_clear_error(&error);

		return reply;
	}

	__netconfig_agent_clear_fields();
	g_variant_get(fields, "a{sv}", &iter);
	while (g_variant_iter_loop(iter, "{sv}", &field, &value)) {
		if (g_strcmp0(field, NETCONFIG_AGENT_FIELD_PASSPHRASE) == 0) {
			g_free(agent.passphrase);
			if (g_variant_is_of_type(value, G_VARIANT_TYPE_STRING)) {
				agent.passphrase = g_strdup(g_variant_get_string(value, NULL));
				updated = TRUE;

				DBG("Field [%s] - []", field);
			} else {
				agent.passphrase = NULL;
			}
		} else if (g_strcmp0(field, NETCONFIG_AGENT_FIELD_WPS_PBC) == 0) {
			agent.wps_pbc = FALSE;
			if (g_variant_is_of_type(value, G_VARIANT_TYPE_STRING) &&
					g_strcmp0(g_variant_get_string(value, NULL), "enable") == 0) {
				agent.wps_pbc = TRUE;
				updated = TRUE;

				DBG("Field [%s] - [%d]", field, agent.wps_pbc);
			}
		} else if (g_strcmp0(field, NETCONFIG_AGENT_FIELD_WPS_PIN) == 0) {
			g_free(agent.wps_pin);
			agent.wps_pbc = FALSE;
			if (g_variant_is_of_type(value, G_VARIANT_TYPE_STRING)) {
				agent.wps_pin = g_strdup(g_variant_get_string(value, NULL));
				updated = TRUE;

				DBG("Field [%s] - []", field);
			} else {
				agent.wps_pin = NULL;
			}
		} else if (g_strcmp0(field, NETCONFIG_AGENT_FIELD_NAME) == 0) {
			g_free(agent.name);
			if (g_variant_is_of_type(value, G_VARIANT_TYPE_STRING)) {
				agent.name = g_strdup(g_variant_get_string(value, NULL));
				updated = TRUE;

				DBG("Field [%s] - []", field);
			} else {
				agent.name = NULL;
			}
		} else if (g_strcmp0(field, NETCONFIG_AGENT_FIELD_SSID) == 0) {
			if (agent.ssid != NULL) {
				g_byte_array_free(agent.ssid, TRUE);
				agent.ssid = NULL;
			}

			if (g_variant_is_of_type(value, G_VARIANT_TYPE_BYTESTRING)) {
				guint8 char_value;
				GVariantIter *iter1;
				GByteArray *array = g_byte_array_new();

				g_variant_get(value, "ay", &iter1);
				while(g_variant_iter_loop(iter1, "y",  &char_value)) {
					g_byte_array_append(array, &char_value, 1);
				}
				g_variant_iter_free(iter1);
				if (array != NULL && (array->len > 0)) {
					agent.ssid = g_byte_array_sized_new(array->len);
					agent.ssid->len = array->len;
					memcpy(agent.ssid->data, array->data, array->len);
					updated = TRUE;

					DBG("Field [%s] - []", field);
				}
			}
		} else if (g_strcmp0(field, NETCONFIG_AGENT_FIELD_IDENTITY) == 0) {
			g_free(agent.identity);
			if (g_variant_is_of_type(value, G_VARIANT_TYPE_STRING)) {
				agent.identity = g_strdup(g_variant_get_string(value, NULL));
				updated = TRUE;

				DBG("Field [%s] - []", field);
			} else {
				agent.identity = NULL;
			}
		}
	}

	if (updated == TRUE) {
		reply = netconfig_invoke_dbus_method_nonblock(CONNMAN_SERVICE,
				service, CONNMAN_SERVICE_INTERFACE, "Connect", NULL, NULL);
		if (reply == TRUE) {
			g_dbus_method_invocation_return_value (context, NULL);
		} else {
			error = g_error_new(G_DBUS_ERROR,
					G_DBUS_ERROR_AUTH_FAILED,
					CONNMAN_ERROR_INTERFACE ".InvalidArguments");

			g_dbus_method_invocation_return_gerror(context, error);
			g_clear_error(&error);
		}
	} else {
		error = g_error_new(G_DBUS_ERROR,
				G_DBUS_ERROR_AUTH_FAILED,
				CONNMAN_ERROR_INTERFACE ".InvalidArguments");

		g_dbus_method_invocation_return_gerror(context, error);
		g_clear_error(&error);
	}

	if (reply != TRUE) {
		ERR("Fail to connect Wi-Fi");

		__netconfig_agent_clear_fields();
	}
	g_variant_iter_free(iter);

	net_connman_agent_complete_set_field(connman_agent, context);
	return reply;
}

gboolean handle_request_input(NetConnmanAgent *connman_agent,
		GDBusMethodInvocation *context, const gchar *service, GVariant *fields)
{
	GVariantIter *iter;
	gchar *field = NULL;
	GVariant *r_value = NULL;
	GVariant *out_table = NULL;
	gboolean updated = FALSE;
	GVariantBuilder *builder = NULL;

	g_return_val_if_fail(connman_agent != NULL, FALSE);

	if (NULL == service)
		return FALSE;

	DBG("Agent fields requested for service: %s", service);

	builder = g_variant_builder_new(G_VARIANT_TYPE ("a{sv}"));

	g_variant_get(fields, "a{sv}", &iter);
	while (g_variant_iter_loop(iter, "{sv}", &field, &r_value)) {

		if (g_strcmp0(field, NETCONFIG_AGENT_FIELD_PASSPHRASE) == 0 &&
				agent.passphrase != NULL) {
			g_variant_builder_add(builder, "{sv}", NETCONFIG_AGENT_FIELD_PASSPHRASE,
							g_variant_new_string(agent.passphrase));

			updated = TRUE;
			DBG("Setting [%s] - []", field);
		} else if (g_strcmp0(field, NETCONFIG_AGENT_FIELD_WPS) == 0 &&
				(agent.wps_pbc == TRUE || agent.wps_pin != NULL)) {
			if (agent.wps_pbc == TRUE) {
				// Sending empty string for WPS push button method
				g_variant_builder_add(builder, "{sv}", NETCONFIG_AGENT_FIELD_WPS, g_variant_new_string(""));

				updated = TRUE;
				DBG("Setting empty string for [%s]", field);
			} else if (agent.wps_pin != NULL) {
				g_variant_builder_add(builder, "{sv}", NETCONFIG_AGENT_FIELD_WPS, g_variant_new_string(agent.wps_pin));

				updated = TRUE;
				DBG("Setting string [%s] - []", field);
			}
		} else if (g_strcmp0(field, NETCONFIG_AGENT_FIELD_NAME) == 0 &&
				agent.name != NULL) {
			g_variant_builder_add(builder, "{sv}", NETCONFIG_AGENT_FIELD_NAME, g_variant_new_string(agent.name));

			updated = TRUE;
			DBG("Settings [%s] - []", field);
		} else if (g_strcmp0(field, NETCONFIG_AGENT_FIELD_SSID) == 0 &&
				agent.ssid != NULL) {
			int i = 0;
			GVariantBuilder *builder1 = NULL;
			builder1 = g_variant_builder_new (G_VARIANT_TYPE ("ay"));

			for (i = 0; i < (agent.ssid->len); i++) {
				g_variant_builder_add (builder1, "y", agent.ssid->data[i]);
			}

			g_variant_builder_add(builder, "{sv}", NETCONFIG_AGENT_FIELD_SSID, g_variant_builder_end(builder1));
			if (builder1 != NULL)
				g_variant_builder_unref(builder1);

			updated = TRUE;
			DBG("Settings [%s] - []", field);
		} else if (g_strcmp0(field, NETCONFIG_AGENT_FIELD_IDENTITY) == 0 &&
				agent.identity != NULL) {
			g_variant_builder_add(builder, "{sv}", NETCONFIG_AGENT_FIELD_IDENTITY, g_variant_new_string(agent.identity));

			updated = TRUE;
			DBG("Settings [%s] - []", field);
		}
	}

	out_table = g_variant_new("(@a{sv})", g_variant_builder_end(builder));

	if (builder)
		g_variant_builder_unref(builder);

	g_variant_iter_free(iter);


	if (NULL == out_table){
		net_connman_agent_complete_request_input(connman_agent, context, out_table);

		return FALSE;
	}

	if (updated == TRUE)
		g_dbus_method_invocation_return_value (context, out_table);
	else {
		GError *error = NULL;
		error = g_error_new(G_DBUS_ERROR,
				G_DBUS_ERROR_AUTH_FAILED,
				"net.connman.Agent.Error.Canceled");

		g_dbus_method_invocation_return_gerror(context, error);
		g_clear_error(&error);
	}

	__netconfig_agent_clear_fields();
	g_variant_unref(out_table);

	return updated;
}


gboolean handle_report_error(NetConnmanAgent *connman_agent,
		GDBusMethodInvocation *context, const gchar *service, const gchar *error)
{
	gboolean ret = TRUE;

	g_return_val_if_fail(connman_agent != NULL, FALSE);

	net_connman_agent_complete_report_error(connman_agent, context);
	DBG("Agent error for service[%s] - [%s]", service, error);

	// Do something when it failed to make a connection

	return ret;
}

#if defined TIZEN_CAPTIVE_PORTAL
#if defined TIZEN_WEARABLE
#define QUERY_FOR_INTERNET_INTERVAL			2
#define TIMER_THRESHOLD						4
#else
#define QUERY_FOR_INTERNET_INTERVAL			20
#define TIMER_THRESHOLD						120
#endif

static gboolean is_monitor_notifier_registered = FALSE;

#if defined TIZEN_WEARABLE
static gboolean is_portal_msg_shown = FALSE;
static guint portal_msg_timer = 0;
#endif

struct poll_timer_data {
	guint time_elapsed;
	guint timer_id;
	void* data;
};

static struct poll_timer_data timer_data =
			{QUERY_FOR_INTERNET_INTERVAL, 0, NULL};

static gboolean __check_ignore_portal_list(const char * ssid)
{
	char def_str[1024];
	int i = 0;
	int ignore_ap_count = 0;

	if (ssid == NULL)
		return FALSE;

	DBG("checking ssid [%s]", ssid);

	DBG("csc string [%s]", def_str);
	gchar ** ignore_ap_list = g_strsplit(def_str, ",", 0);
	ignore_ap_count = g_strv_length(ignore_ap_list);
	for(i = 0; i < ignore_ap_count; i++) {
		DBG("[%d] - [%s]", i, ignore_ap_list[i]);
		if (strncmp(ignore_ap_list[i], ssid, strlen(ssid)) == 0) {
			g_strfreev(ignore_ap_list);
			return TRUE;
		}
	}

	g_strfreev(ignore_ap_list);
	return FALSE;
}

static void __wifi_state_monitor(wifi_service_state_e state,
		void *user_data);

static wifi_state_notifier wifi_state_monitor_notifier = {
		.wifi_state_changed = __wifi_state_monitor,
		.user_data = NULL,
};

static void __wifi_state_monitor(wifi_service_state_e state,
		void *user_data)
{
	DBG("Wi-Fi state: %x", state);

	if (state == NETCONFIG_WIFI_CONNECTED)
		return;

	if (is_monitor_notifier_registered == TRUE) {
		wifi_state_notifier_unregister(&wifi_state_monitor_notifier);
		is_monitor_notifier_registered = FALSE;
	}

#if defined TIZEN_WEARABLE
	is_portal_msg_shown = FALSE;
#endif

	/* suspend if Internet check activity in progress */
	if (timer_data.timer_id == 0)
		return;

	netconfig_stop_timer(&timer_data.timer_id);
	netconfig_stop_internet_check();

	DBG("Stopped Internet accessibility check");
}

static gboolean __netconfig_wifi_portal_login_timeout(gpointer data)
{
	char *service_profile = NULL;
	GVariant *reply = NULL;

	DBG("");

	struct poll_timer_data *timer = (struct poll_timer_data *)data;
	if (timer == NULL)
		return FALSE;

	if (TRUE == netconfig_get_internet_status()) {
		if (is_monitor_notifier_registered == TRUE) {
			wifi_state_notifier_unregister(&wifi_state_monitor_notifier);
			is_monitor_notifier_registered = FALSE;
		}

		DBG("Portal logged in successfully and update ConnMan state");
		return FALSE; /* to stop the timer */
	} else {
		if (timer->time_elapsed >= TIMER_THRESHOLD) {
			DBG("Login failed, update ConnMan");

			if (is_monitor_notifier_registered == TRUE) {
				wifi_state_notifier_unregister(&wifi_state_monitor_notifier);
				is_monitor_notifier_registered = FALSE;
			}

			/* Disconnect and forget the AP */
			service_profile = (char*) netconfig_get_default_profile();
			if (service_profile && netconfig_is_wifi_profile(service_profile)) {
				/* Now forget the AP*/
				reply = netconfig_invoke_dbus_method(CONNMAN_SERVICE,
						service_profile, CONNMAN_SERVICE_INTERFACE, "Remove",
						NULL);

				if (reply != NULL)
					g_variant_unref(reply);
				else
					ERR("Failed to forget the AP ");
			}
		} else {
			if (NETCONFIG_WIFI_CONNECTED ==
					wifi_state_get_service_state()) {
				/* check Internet availability by sending and receiving data*/
				netconfig_check_internet_accessibility();
				/* Returning TRUE itself is enough to restart the timer */
				timer->time_elapsed = timer->time_elapsed +
									QUERY_FOR_INTERNET_INTERVAL;
				return TRUE;
			}
		}
	}

	return FALSE;
}

#if defined TIZEN_WEARABLE
static gboolean __netconfig_display_portal_msg(gpointer data)
{
	DBG("");
	wc_launch_popup(WC_POPUP_TYPE_CAPTIVE_PORTAL);

	netconfig_stop_timer(&portal_msg_timer);

	return FALSE;
}
#endif

static void __netconfig_wifi_portal_login_timer_start(struct poll_timer_data
		*data)
{
	DBG("__netconfig_wifi_browser_start_timer...starting timer");

	if (data == NULL)
		return;

	netconfig_stop_timer(&(data->timer_id));

	/* Timer logic: After successful launch of browser, we would check for
	 * Internet status for every 20s until a threshold of 120s
	 */

	data->time_elapsed = QUERY_FOR_INTERNET_INTERVAL;
	netconfig_start_timer_seconds(QUERY_FOR_INTERNET_INTERVAL,
		__netconfig_wifi_portal_login_timeout, data, &(data->timer_id));
}
#endif

gboolean handle_request_browser(NetConnmanAgent *connman_agent,
		GDBusMethodInvocation *context, const gchar *service, const gchar *url)
{
#if defined TIZEN_CAPTIVE_PORTAL
	gboolean ret = FALSE;
	gboolean ignore_portal = FALSE;
	const char * ssid = NULL;

	g_return_val_if_fail(connman_agent != NULL, FALSE);

	DBG("service[%s] - url[%s]", service, url);

	ssid = netconfig_wifi_get_connected_essid(netconfig_get_default_profile());
	if (ssid == NULL) {
		ERR("Connected AP name is NULL!!");
		net_connman_agent_complete_request_browser(connman_agent, context);
		return FALSE;
	}

	ignore_portal = __check_ignore_portal_list(ssid);

	if (ignore_portal == TRUE){
		net_connman_agent_complete_request_browser(connman_agent, context);
		return TRUE;
	}
	/* Register for Wifi state change notifier*/
	if (is_monitor_notifier_registered == FALSE) {
		wifi_state_notifier_register(&wifi_state_monitor_notifier);
		is_monitor_notifier_registered = TRUE;
	}

#if defined TIZEN_WEARABLE
	if (is_portal_msg_shown){
		net_connman_agent_complete_request_browser(connman_agent, context);
		return TRUE;
	}

	is_portal_msg_shown = TRUE;
	netconfig_start_timer_seconds(4, __netconfig_display_portal_msg, NULL, &portal_msg_timer);
#else
	ret = netconfig_send_notification_to_net_popup(NETCONFIG_ADD_PORTAL_NOTI, ssid);
#endif

	timer_data.time_elapsed = 0;
	__netconfig_wifi_portal_login_timer_start(&timer_data);

	net_connman_agent_complete_request_browser(connman_agent, context);
	return ret;
#else
	GError *error = NULL;
	error = g_error_new(G_DBUS_ERROR,
			G_DBUS_ERROR_AUTH_FAILED,
			CONNMAN_ERROR_INTERFACE ".NotSupported");

	g_dbus_method_invocation_return_gerror(context, error);
	g_clear_error(&error);

	return FALSE;
#endif
}
