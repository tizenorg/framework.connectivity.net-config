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

#include <alarm.h>
#include <vconf.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <vconf-keys.h>

#include "log.h"
#include "util.h"
#include "wifi-state.h"
#include "wifi-power.h"
#include "netsupplicant.h"
#include "wifi-powersave.h"
#include "wifi-background-scan.h"

#define VCONF_WIFI_SLEEPPOLICY		"file/private/wifi/sleep_policy"
#define NETCONFIG_POWERSAVE_DELAY	900 /* 15 mins */

enum netconfig_wifi_powersave_mode {
	NETCONFIG_WIFI_ALWAYS_KEEP_CONNECTED =				0x00,
	NETCONFIG_WIFI_KEEP_CONNECTED_WHEN_PLUGGED_IN =		0x01,
	NETCONFIG_WIFI_NEVER_KEEP =							0x02,
};

struct netconfig_wifi_priv_cmd {
	char *buf;
	int used_len;
	int total_len;
};


static alarm_id_t netconfig_wifi_powersave_timer_id = 0;
static gboolean netconfig_wifi_powersave_state = FALSE;

static void __netconfig_wifi_powersave_start_alarm_timer(void)
{
	int result;

	result = alarmmgr_add_alarm(ALARM_TYPE_VOLATILE, NETCONFIG_POWERSAVE_DELAY,
			0, NULL, &netconfig_wifi_powersave_timer_id);
	if (result == ALARMMGR_RESULT_SUCCESS)
		DBG("Deep sleep mode alarm added successfully -[%d]",
				netconfig_wifi_powersave_timer_id);
	else
		DBG("Deep sleep mode alarm add failed - [%d]", result);
}

static void __netconfig_wifi_powersave_stop_alarm_timer(int alarm_id)
{
	int result;

	result = alarmmgr_remove_alarm(alarm_id);
	if (result == ALARMMGR_RESULT_SUCCESS) {
		netconfig_wifi_powersave_timer_id = 0;
		DBG("Deep sleep mode alarm removed successfully - [%d]", alarm_id);
	} else
		DBG("Deep sleep mode alarm remove failed - [%d]", result);
}

static void __netconfig_wifi_powersave_private_cmd(gboolean start)
{
	int fd;
	char buf[8192] = { 0, };
	const char *START = "START";
	const char *STOP = "STOP";
	const char *cmd;

	struct ifreq ifr;
	struct netconfig_wifi_priv_cmd priv_cmd;

	fd = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return;

	memset(&ifr, 0, sizeof(ifr));
	memset(&priv_cmd, 0, sizeof(priv_cmd));
	g_strlcpy(ifr.ifr_name, WIFI_IFNAME, IFNAMSIZ);

	if (start == TRUE)
		cmd = START;
	else
		cmd = STOP;
	g_strlcpy(buf, cmd, sizeof(buf));
	priv_cmd.buf = buf;
	priv_cmd.used_len = 8192;
	priv_cmd.total_len = 8192;
	ifr.ifr_data = (void *)&priv_cmd;

	if (ioctl(fd, SIOCDEVPRIVATE + 1, &ifr) < 0)
		ERR("Failed private command %s and reply %s", cmd, buf);

	DBG("Private command %s and reply %s", cmd, buf);
	close(fd);
}

int __netconfig_wifi_powersave_timer_expired(alarm_id_t alarm_id,
		void *user_param)
{
	DBG("Wi-Fi power save mode");

	netconfig_wifi_powersave_state = TRUE;

	__netconfig_wifi_powersave_stop_alarm_timer(alarm_id);

	__netconfig_wifi_powersave_private_cmd(TRUE);

	netconfig_wifi_bgscan_stop();

	netconfig_wifi_off();

	return 0;
}

void netconfig_wifi_early_suspend(gboolean value)
{
	static gboolean old_state = FALSE;
	struct ifreq ifr;
	char buf[248] = { '\0' }; /* Max driver command size is 248 */
	struct netconfig_wifi_priv_cmd priv_cmd;
	int ret = 0;
	int ioctl_sock = 0;
	int pm_state = 0;
	enum netconfig_wifi_service_state wifi_state;
	size_t buf_len;

	if (old_state == value)
		return;

	if (vconf_get_int(VCONFKEY_PM_STATE, &pm_state) < 0)
		ERR("Fail to get VCONFKEY_PM_STATE");

	wifi_state = netconfig_wifi_state_get_service_state();

	if (value == TRUE &&
			(pm_state < VCONFKEY_PM_STATE_LCDOFF ||
			wifi_state == NETCONFIG_WIFI_ASSOCIATION ||
			wifi_state == NETCONFIG_WIFI_CONFIGURATION))
		return;

	g_snprintf(buf, sizeof(buf), "SETSUSPENDMODE %d", value);

	memset(&ifr, 0, sizeof(struct ifreq));
	g_strlcpy((char *)ifr.ifr_name, WIFI_IFNAME, IFNAMSIZ);

	DBG("Early suspend command: [%s]", buf);

	memset(&priv_cmd, 0, sizeof(priv_cmd));
	buf_len = strlen(buf);
	priv_cmd.buf = buf;
	priv_cmd.used_len = buf_len;
	priv_cmd.total_len = buf_len;
	ifr.ifr_data = (char *)&priv_cmd;

	ioctl_sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (ioctl_sock < 0) {
		DBG("socket(PF_INET,SOCK_DGRAM) failed");
		return;
	}

	ret = ioctl(ioctl_sock, SIOCDEVPRIVATE + 1, &ifr);
	if (ret < 0)
		ERR("Fail to issue private commands: %d", ret);
	else
		old_state = value;

	close(ioctl_sock);
}

gboolean netconfig_wifi_is_powersave_mode(void)
{
	return netconfig_wifi_powersave_state;
}

void netconfig_wifi_powersave_start(void)
{
	int powersave_policy = 0;
	int charger_state = 0;

	if (netconfig_wifi_state_get_service_state() != NETCONFIG_WIFI_CONNECTED)
		return;

	DBG("Check Wi-Fi deep sleep mode activation");

	/* Deep sleep policy options
	 * 0 : Always - Wi-Fi always ON; No need to handle deep sleep mode
	 * 1 : Plugged-in - Handle deep sleep mode only when phone plugged-in
	 * 2 : Never - Handle deep sleep mode always
	 */
	if (vconf_get_int(VCONF_WIFI_SLEEPPOLICY, &powersave_policy) < 0) {
		ERR("Fail to get VCONF_WIFI_SLEEPPOLICY");
		return;
	}
	DBG("Deep sleep policy: %d", powersave_policy);

	if (powersave_policy == NETCONFIG_WIFI_KEEP_CONNECTED_WHEN_PLUGGED_IN) {
		/* Charger connection status
		 * VCONFKEY_SYSMAN_CHARGER_DISCONNECTED = 0
		 * VCONFKEY_SYSMAN_CHARGER_CONNECTED
		 */
		if (vconf_get_int(VCONFKEY_SYSMAN_CHARGER_STATUS, &charger_state) < 0) {
			ERR("Fail to get VCONFKEY_SYSMAN_CHARGER_STATUS");
			return;
		}
		DBG("Charger status: %d", charger_state);
	}

	if (powersave_policy == NETCONFIG_WIFI_NEVER_KEEP ||
			(powersave_policy == NETCONFIG_WIFI_KEEP_CONNECTED_WHEN_PLUGGED_IN &&
					charger_state == VCONFKEY_SYSMAN_CHARGER_DISCONNECTED))
		__netconfig_wifi_powersave_start_alarm_timer();
}

void netconfig_wifi_powersave_stop(void)
{
	DBG("Check Wi-Fi deep sleep mode de-activation");

	if (netconfig_wifi_powersave_state == TRUE) {
		DBG("Out of deep sleep mode");

		__netconfig_wifi_powersave_private_cmd(FALSE);

		netconfig_wifi_on();

		netconfig_wifi_powersave_state = FALSE;
	} else
		__netconfig_wifi_powersave_stop_alarm_timer(
				netconfig_wifi_powersave_timer_id);
}

void netconfig_wifi_powersave_init(void)
{
	int result;

	result = alarmmgr_init(PACKAGE);
	if (result == ALARMMGR_RESULT_SUCCESS) {
		DBG("Alarm manager init successful");

		result = alarmmgr_set_cb(__netconfig_wifi_powersave_timer_expired, NULL);
		if (result == ALARMMGR_RESULT_SUCCESS)
			DBG("Alarm manager set callback successful");
		else
			DBG("Alarm manager set callback failed - [%d]", result);
	} else
		DBG("Alarm manager init failed - [%d]", result);
}

void netconfig_wifi_powersave_deinit(void)
{
	alarmmgr_fini();
}
