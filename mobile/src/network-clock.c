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
}

static gboolean __netconfig_clock_clear_timeserver_timer(gpointer data)
{
	INFO("Clear NTP server");

	__netconfig_clock_clear_timeserver();

	return FALSE;
}

static void __netconfig_clock_set_timeserver(const char *server)
{
	DBusMessage* reply = NULL;
	char param1[] = "string:Timeservers";
	char *param2 = NULL;
	char *param_array[] = {NULL, NULL, NULL};

	param2 = g_strdup_printf("variant:array:string:%s", server);

	param_array[0] = param1;
	param_array[1] = param2;

	reply = netconfig_invoke_dbus_method(CONNMAN_SERVICE,
			CONNMAN_MANAGER_PATH, CONNMAN_CLOCK_INTERFACE,
			"SetProperty", param_array);
	if (reply == NULL) {
		ERR("Failed to configure NTP server");
		return;
	}

	dbus_message_unref(reply);
}

static void __netconfig_clock(
		enum netconfig_wifi_service_state state, void *user_data)
{
	gboolean automatic_time_update = 0;
	guint timeserver_clear_timer = 0;

	if (state != NETCONFIG_WIFI_CONNECTED)
		return;

	vconf_get_bool(
			VCONFKEY_SETAPPL_STATE_AUTOMATIC_TIME_UPDATE_BOOL,
			&automatic_time_update);

	if (automatic_time_update == FALSE) {
		INFO("Automatic time update is not set (%d)", automatic_time_update);
		return;
	}

	__netconfig_clock_set_timeserver((const char *)NTP_SERVER);

	netconfig_start_timer_seconds(5, __netconfig_clock_clear_timeserver_timer,
			NULL, &timeserver_clear_timer);
}

static struct netconfig_wifi_state_notifier netconfig_clock_notifier = {
		.netconfig_wifi_state_changed = __netconfig_clock,
		.user_data = NULL,
};

void netconfig_clock_init(void)
{
	netconfig_wifi_state_notifier_register(&netconfig_clock_notifier);
}

void netconfig_clock_deinit(void)
{
	netconfig_wifi_state_notifier_unregister(&netconfig_clock_notifier);
}
