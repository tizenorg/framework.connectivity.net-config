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

#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/utsname.h>
#include <vconf.h>
#include <vconf-keys.h>

#include "log.h"
#include "emulator.h"

static gboolean netconfig_is_emulated = FALSE;

static gboolean __netconfig_emulator_test_emulation_env(void)
{
	struct utsname buf;
	const char *EMUL_UTSNAME_MACHINE_SUFFIX = "emulated";

	DBG("Test emulation environment");

	uname(&buf);

	if (g_str_has_suffix(buf.machine, EMUL_UTSNAME_MACHINE_SUFFIX) == TRUE)
		return TRUE;

	return FALSE;
}

static void __netconfig_emulator_set_ip(void)
{
	const char EMUL_IFNAME[] = "eth0";
	char ip[30] = { 0, };
	int sockfd = 0;
	struct ifreq ifr;

	sockfd = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (sockfd < 0) {
		ERR("Failed to open socket");
		return;
	}

	memset(&ifr, 0, sizeof(struct ifreq));
	g_strlcpy((char *)ifr.ifr_name, EMUL_IFNAME, 16);

	if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
		ERR("Failed to get IP address");

		close(sockfd);
		return;
	}

	close(sockfd);

	g_strlcpy(ip,
			inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr), 30);

	vconf_set_str(VCONFKEY_NETWORK_IP, ip);
}

static void __netconfig_emulator_set_proxy(void)
{
	const char HTTP_PROXY[] = "http_proxy";
	char *proxy = NULL;

	proxy = getenv(HTTP_PROXY);
	DBG("Get system proxy: %s", proxy);

	if(proxy != NULL)
		vconf_set_str(VCONFKEY_NETWORK_PROXY, proxy);
}

static void __netconfig_emulator_set_network_state(void)
{
	vconf_set_int(VCONFKEY_NETWORK_CONFIGURATION_CHANGE_IND, 1);
	vconf_set_int(VCONFKEY_NETWORK_STATUS, VCONFKEY_NETWORK_CELLULAR);
	vconf_set_int(VCONFKEY_DNET_STATE, VCONFKEY_DNET_NORMAL_CONNECTED);
}

static void __netconfig_emulator_config_emul_env(void)
{
	__netconfig_emulator_set_ip();
	__netconfig_emulator_set_proxy();
	__netconfig_emulator_set_network_state();
}

gboolean netconfig_emulator_is_emulated(void)
{
	return netconfig_is_emulated;
}

void netconfig_emulator_test_and_start(void)
{
	netconfig_is_emulated = __netconfig_emulator_test_emulation_env();

	DBG("Emulation environment tested: %s", netconfig_is_emulated ?
			"It's emulated" : "Not emulated");

	if (netconfig_is_emulated == TRUE)
		__netconfig_emulator_config_emul_env();
}
