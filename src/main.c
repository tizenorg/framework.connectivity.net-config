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
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <system_info.h>

#include "log.h"
#include "wifi.h"
#include "netdbus.h"
#include "emulator.h"
#include "neterror.h"
#include "wifi-agent.h"
#include "wifi-power.h"
#include "network-clock.h"
#include "network-state.h"
#include "network-monitor.h"
#include "signal-handler.h"
#include "network-statistics.h"

static GMainLoop *main_loop = NULL;

#define ETHERNET_FEATURE       "http://tizen.org/feature/network.ethernet"

/*Poll the ethernet Cable Plug-in /Plug-out status at every 1000 ms*/
#define ETH_POLLING_TIME       1000

/* Callback to Poll the Ethernet Status*/
gboolean __net_ethernet_cable_status_polling_callback(gpointer data)
{
	netconfig_ethernet_cable_plugin_status_check();
	return TRUE;
}

void _got_name_cb(void)
{
	wifi_object_create_and_init();
	state_object_create_and_init();
	statistics_object_create_and_init();

	register_gdbus_signal();
	connman_register_agent();

#if defined TIZEN_TV
	__netconfig_set_ether_macaddr();
#endif
}

static void _objects_deinit(void)
{
	cleanup_gdbus();
	wifi_object_deinit();
	state_object_deinit();
	statistics_object_deinit();
}

int main(int argc, char *argv[])
{
	int ret;
	int check_ethernet_monitor_timer = 0;
	bool ethernet_feature_supported = FALSE;

	umask(0077);

	DBG("Network Configuration service");
	if (daemon(0, 0) != 0)
		DBG("Cannot start daemon");

	if (mkdir(WIFI_STORAGEDIR, S_IRUSR | S_IWUSR | S_IXUSR |
			S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) < 0) {
		if (errno != EEXIST)
			ERR("Failed to create Wi-Fi directory");
	}

	if (mkdir(WIFI_CERT_STORAGEDIR, S_IRUSR | S_IWUSR | S_IXUSR |
			S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH) < 0) {
		if (errno != EEXIST)
			ERR("Failed to create cert directory");
	}

#if !GLIB_CHECK_VERSION(2,36,0)
	g_type_init();
#endif

	main_loop = g_main_loop_new(NULL, FALSE);
	if (main_loop == NULL) {
		ERR("Couldn't create GMainLoop\n");
		return 0;
	}

	ret = setup_gdbus(_got_name_cb);
	if (ret > 0) {
		ERR("_netconfig_setup_gdbus is failed\n");
		return 0;
	}

	netconfig_error_init();

#if !defined TIZEN_TELEPHONY_ENABLE
	netconfig_clock_init();
#endif

	/* If its environment uses Emulator, network configuration is set by emulator default */
	emulator_test_and_start();


	/*In case no emulator, set the ETH0 Mac address*/
#if defined TIZEN_TV
	if (emulator_is_emulated() == FALSE)
		__netconfig_set_ether_macaddr();
#endif

	if (!system_info_get_platform_bool(ETHERNET_FEATURE, &ethernet_feature_supported)) {
		if (ethernet_feature_supported == TRUE) {
			//Register the callback to check the ethernet Plug-in /Plug-out Status
			check_ethernet_monitor_timer = g_timeout_add(ETH_POLLING_TIME,
					__net_ethernet_cable_status_polling_callback,
					&check_ethernet_monitor_timer);
		}
	} else {
		ERR("Error - Feature getting from System Info");
	}

	g_main_loop_run(main_loop);

	_objects_deinit();

	log_cleanup();

	deregister_gdbus_signal();

#if !defined TIZEN_TELEPHONY_ENABLE
	netconfig_clock_deinit();
#endif


	/*remove the Timer*/
	if(check_ethernet_monitor_timer >0)
		g_source_remove(check_ethernet_monitor_timer);

	wifi_state_notifier_cleanup();

	/* Unregistering the agent */
	connman_unregister_agent();

	return 0;
}
