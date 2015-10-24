/*
 * Network Configuration Module
 *
 * Copyright (c) 2015 Samsung Electronics Co., Ltd. All rights reserved.
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
#include <stdlib.h>

#include "log.h"
#include "util.h"
#include "network-state.h"
#include "clatd-handler.h"

#define CLAT_EXEC_PATH "/usr/sbin/clatd"
#define ROUTE_EXEC_PATH "/sbin/route"
#define KILLALL_EXEC_PATH "/usr/bin/killall"
#define IFCONFIG_EXEC_PATH "/sbin/ifconfig"

char g_ifname[32] = {0, };

int netconfig_clatd_enable(void)
{
	int rv = 0;

	if (g_ifname[0] != '\0') {
		rv = netconfig_clatd_disable();

		if (rv < 0) {
			DBG("Failed to disable existing clatd process");
			return -1;
		}
	}

	const char *if_name = netconfig_get_default_ifname();

	if (if_name == NULL) {
		DBG("There is no interface name");
		return -1;
	}

	memset(g_ifname, 0, sizeof(g_ifname));
	g_strlcat(g_ifname, if_name, 32);

	const char *path = CLAT_EXEC_PATH;
	char *const args[] = { "/usr/sbin/clatd", "-i", g_ifname, NULL };

	rv = netconfig_execute_clatd(path, args);

	if (rv < 0) {
		DBG("Failed to enable clatd process %d", rv);
		return -1;
	}

	DBG("Successfully enabled clatd process with %s interface", g_ifname);
	return 0;
}

int netconfig_clatd_disable(void)
{
	int rv = 0;

	const char *path = KILLALL_EXEC_PATH;
	char *const args[] = { "/usr/bin/kill -15", "clatd", NULL };
	char *const envs[] = { NULL };

	if (g_ifname[0] == '\0') {
		DBG("There is no clatd process");
		return -1;
	}

	memset(g_ifname, 0, sizeof(g_ifname));

	rv = netconfig_execute_file(path, args, envs);

	if (rv < 0) {
		DBG("Failed to disable clatd process %d", rv);
		return -1;
	}

	DBG("Successfully disable clatd process");;
	return 0;
}
