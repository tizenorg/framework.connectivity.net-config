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

#include <systemd/sd-daemon.h>
#include <getopt.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>

#include "log.h"
#include "wifi.h"
#include "util.h"
#include "emulator.h"
#include "netdbus.h"
#include "network-clock.h"
#include "network-state.h"
#include "network-statistics.h"
#include "signal-handler.h"
#include "wifi-agent.h"

static GMainLoop *main_loop = NULL;

static int no_fork = FALSE;

void netconfig_signal_handler_SIGTERM(int signum)
{
	g_main_loop_quit(main_loop);
}

int netconfig_register_signal_handler_SIGTERM(void)
{
	struct sigaction sigset;

	sigemptyset(&sigset.sa_mask);
	sigaddset( &sigset.sa_mask, SIGTERM );
	sigset.sa_flags = 0;
	sigset.sa_handler = netconfig_signal_handler_SIGTERM;

	if (sigaction( SIGTERM, &sigset, NULL) < 0) {
		ERR("Sigaction for SIGTERM failed [%s]", strerror( errno ));
		return -1;
	}

	INFO( "Handler for SIGTERM ok" );
	return 0;
}

int netconfig_test_input_parameters(int argc, char* argv[])
{
        struct option tab[] = {
                { "nofork", no_argument, 0, 0 },
                { NULL, 0, NULL, 0 }
        };
        int idx = 0;

        while (getopt_long(argc, argv, "", tab, &idx) >= 0) {

		if (idx == 0)
			no_fork = TRUE;
		idx = 0;
	}
	return 0;
}

int main(int argc, char* argv[])
{
	DBusGConnection *connection;

	DBG("Network Configuration Module");

	/*
	 * Call parameters veryfication
	 */
	netconfig_test_input_parameters(argc, argv);

	if (!no_fork) {
		if (daemon(0, 0) != 0)
			DBG("Cannot start daemon");
	}

	netconfig_set_wifi_mac_address();

	g_type_init();

	main_loop = g_main_loop_new(NULL, FALSE);

	connection = netconfig_setup_dbus();
	if (connection == NULL)
		return -1;

	if (netconfig_network_state_create_and_init(connection) == NULL)
		return -1;

	netconfig_register_signal();

	/* Registering the agent for exchanging security credentials */
	netconfig_agent_register();

	if (netconfig_wifi_create_and_init(connection) == NULL)
		return -1;

	if (netconfig_network_statistics_create_and_init(connection) == NULL)
		return -1;

	/* Register SIGCHLD signal handler function */
	if (netconfig_register_signal_handler_SIGTERM() != 0)
		return -1;

	/* If its environment uses Emulator, network configuration is set by emulator default */
	netconfig_emulator_test_and_start();

	// Notyfication to systemd
	sd_notify(0, "READY=1");

	g_main_loop_run(main_loop);

	netconfig_deregister_signal();
	netconfig_wifi_state_notifier_cleanup();

	/* Unregistering the agent */
	netconfig_agent_unregister();

	return 0;
}
