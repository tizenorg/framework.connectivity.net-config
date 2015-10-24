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

#include <vconf.h>
#include <vconf-keys.h>

#include "log.h"
#include "util.h"
#include "netdbus.h"
#include "wifi-state.h"

#define NTP_SERVER	"pool.ntp.org"
#define CONNMAN_GLOBAL_SETTING	"/var/lib/connman/settings"

static void __netconfig_clock_clear_timeserver(void)
{
	GKeyFile *keyfile = NULL;

	keyfile = netconfig_keyfile_load(CONNMAN_GLOBAL_SETTING);

	if (keyfile == NULL)
		return;

	g_key_file_remove_key(keyfile, "global", "Timeservers", NULL);

	netconfig_keyfile_save(keyfile, CONNMAN_GLOBAL_SETTING);
	g_key_file_free(keyfile);
}

static gboolean __netconfig_clock_clear_timeserver_timer(gpointer data)
{
	INFO("Clear NTP server");

	__netconfig_clock_clear_timeserver();

	return FALSE;
}

static void __netconfig_clock_set_timeserver(const char *server)
{
	GVariant* reply = NULL;
	const char param0[] = "Timeservers";
	GVariant *params = NULL;
	GVariantBuilder *builder;

	builder = g_variant_builder_new(G_VARIANT_TYPE ("as"));
	g_variant_builder_add(builder, "s", server);

	params = g_variant_new("(sv)",param0, g_variant_builder_end(builder));
	g_variant_builder_unref(builder);

	reply = netconfig_invoke_dbus_method(CONNMAN_SERVICE,
			CONNMAN_MANAGER_PATH, CONNMAN_CLOCK_INTERFACE,
			"SetProperty", params);

	if (reply == NULL)
		ERR("Failed to configure NTP server");
	else
		g_variant_unref(reply);

	return;
}

static void __netconfig_set_timeserver(void)
{
	guint timeserver_clear_timer = 0;

	__netconfig_clock_set_timeserver((const char *)NTP_SERVER);

	netconfig_start_timer_seconds(5, __netconfig_clock_clear_timeserver_timer,
			NULL, &timeserver_clear_timer);
}

static void __netconfig_clock(
		wifi_service_state_e state, void *user_data)
{
	gboolean automatic_time_update = 0;

	if (state != NETCONFIG_WIFI_CONNECTED)
		return;

	vconf_get_bool(
			VCONFKEY_SETAPPL_STATE_AUTOMATIC_TIME_UPDATE_BOOL,
			&automatic_time_update);

	if (automatic_time_update == FALSE) {
		INFO("Automatic time update is not set (%d)", automatic_time_update);
		return;
	}

	__netconfig_set_timeserver();
}

static wifi_state_notifier netconfig_clock_notifier = {
		.wifi_state_changed = __netconfig_clock,
		.user_data = NULL,
};

static void __automatic_time_update_changed_cb(keynode_t *node, void *user_data)
{
	gboolean automatic_time_update = FALSE;
	wifi_service_state_e wifi_state = NETCONFIG_WIFI_UNKNOWN;

	if (node != NULL) {
		automatic_time_update = vconf_keynode_get_bool(node);
	} else {
		vconf_get_bool(VCONFKEY_SETAPPL_STATE_AUTOMATIC_TIME_UPDATE_BOOL, &automatic_time_update);
	}

	if (automatic_time_update == FALSE) {
		INFO("Automatic time update is changed to 'FALSE'");
		return;
	}

	 wifi_state = wifi_state_get_service_state();

	 if (wifi_state != NETCONFIG_WIFI_CONNECTED) {
		INFO("WiFi state is not NETCONFIG_WIFI_CONNECTED");
		return;
	 }

	__netconfig_set_timeserver();
}

void netconfig_clock_init(void)
{
	INFO("netconfig_clock_init is called");
	vconf_notify_key_changed(VCONFKEY_SETAPPL_STATE_AUTOMATIC_TIME_UPDATE_BOOL,
			__automatic_time_update_changed_cb, NULL);

	wifi_state_notifier_register(&netconfig_clock_notifier);
}

void netconfig_clock_deinit(void)
{
	wifi_state_notifier_unregister(&netconfig_clock_notifier);
}
