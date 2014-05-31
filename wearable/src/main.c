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

#include <unistd.h>
#include <sys/stat.h>

#include "log.h"
#include "wifi.h"
#include "netdbus.h"
#include "emulator.h"
#include "neterror.h"
#include "wifi-agent.h"
#include "wifi-power.h"
#include "network-clock.h"
#include "network-state.h"
#include "signal-handler.h"
#include "network-statistics.h"

static GMainLoop *main_loop = NULL;

int main(int argc, char *argv[])
{
	DBusGConnection *connection;

	umask(0077);

	DBG("Network Configuration service");

	if (daemon(0, 0) != 0)
		DBG("Cannot start daemon");

	g_type_init();

	main_loop = g_main_loop_new(NULL, FALSE);

	connection = netconfig_setup_dbus();
	if (connection == NULL)
		return -1;

	netconfig_register_signal();

	netconfig_agent_register();

	if (netconfig_wifi_create_and_init(connection) == NULL)
		return -1;

	if (netconfig_network_state_create_and_init(connection) == NULL)
		return -1;

	if (netconfig_network_statistics_create_and_init(connection) == NULL)
		return -1;

	netconfig_error_init();

	/* If its environment uses Emulator, network configuration is set by emulator default */
	netconfig_emulator_test_and_start();

	g_main_loop_run(main_loop);

	netconfig_deregister_signal();

	netconfig_wifi_state_notifier_cleanup();

	/* Unregistering the agent */
	netconfig_agent_unregister();

	return 0;
}
