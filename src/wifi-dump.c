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

#include <glib.h>

#include "log.h"

#include "util.h"
#include "netdbus.h"
#include "wifi-dump.h"

#define NETWORK_DUMP_SCRIPT             "/opt/var/lib/net-config/network_dump.sh"

static int _start_dump(gchar *dump_path)
{
	int rv = 0;
	gchar *path = NETWORK_DUMP_SCRIPT;
	char *const args[] = { "/opt/var/lib/net-config/network_dump.sh", dump_path, NULL };
	char *const envs[] = { NULL };

	rv = netconfig_execute_file(path, args, envs);
	if (rv < 0) {
		ERR("Fail to execute network_dump.sh");
		return -EIO;
	}

	return 0;
}

static void _send_dump_signal(const gchar *sig_name)
{
	gboolean reply;
	GDBusConnection *connection = NULL;
	GError *error = NULL;

	connection = netdbus_get_connection();
	if (connection == NULL) {
		DBG("GDBusconnection is NULL");
		return;
	}

	reply = g_dbus_connection_emit_signal(connection,
			NULL,
			DUMP_SERVICE_OBJECT_PATH,
			DUMP_SERVICE_INTERFACE,
			sig_name,
			NULL,
			&error);
	if (reply != TRUE) {
		if (error != NULL) {
			ERR("Failed to send signal [%s]", error->message);
			g_error_free(error);
		}
		return;
	}
}

int netconfig_dump_log(const char *path)
{
	gchar *dump_path = NULL;

	if (!path) {
		ERR("path is NULL. Dump Fail");
		return -1;
	}
	ERR("Dump is started");
	_send_dump_signal(DUMP_START_SIGNAL);

	dump_path = g_strdup(path);
	_start_dump(dump_path);
	g_free(dump_path);

	_send_dump_signal(DUMP_FINISH_SIGNAL);
	ERR("Dump is finished");
	return 0;
}
