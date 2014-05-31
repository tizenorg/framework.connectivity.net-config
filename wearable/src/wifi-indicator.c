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
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/wireless.h>
#include <vconf.h>
#include <vconf-keys.h>

#include "log.h"
#include "util.h"
#include "netdbus.h"
#include "wifi-state.h"
#include "network-state.h"
#include "network-statistics.h"
#include "netsupplicant.h"
#include "wifi-indicator.h"

#define VCONFKEY_WIFI_SNR_MIN	-89

#define NETCONFIG_WIFI_INDICATOR_INTERVAL	1

#define NETCONFIG_WIFI_DATA_ACTIVITY_BOOSTER_LEVEL1	(19200 * 1024)
#define NETCONFIG_WIFI_DATA_ACTIVITY_BOOSTER_LEVEL2	(7680 * 1024)
#define NETCONFIG_WIFI_DATA_ACTIVITY_BOOSTER_LEVEL3	(3840 * 1024)
#define NETCONFIG_PROCWIRELESS					"/proc/net/wireless"

static int netconfig_wifi_rssi = VCONFKEY_WIFI_SNR_MIN;
static guint netconfig_wifi_indicator_timer = 0;

int netconfig_wifi_get_rssi(void)
{
	return netconfig_wifi_rssi;
}

static int __netconfig_wifi_update_and_get_rssi(void)
{
	FILE *fp;
	char buf[512];
	char *p_ifname = NULL, *p_entry = NULL;
	int rssi_dbm = VCONFKEY_WIFI_SNR_MIN;

	fp = fopen(NETCONFIG_PROCWIRELESS, "r");
	if (fp == NULL) {
		ERR("Failed to open %s", NETCONFIG_PROCWIRELESS);
		return rssi_dbm;
	}

	/* skip the first and second line */
	if (fgets(buf, sizeof(buf), fp) == NULL ||
			fgets(buf, sizeof(buf), fp) == NULL)
		goto endline;

	while (fgets(buf, sizeof(buf), fp)) {
		unsigned int status;
		int link, noise;
		/* No need to read */
		/*
		unsigned long nwid, crypt, frag, retry, misc, missed;
		*/

		p_ifname = buf;
		while (*p_ifname == ' ') p_ifname++;
		p_entry = strchr(p_ifname, ':');
		*p_entry++ = '\0';

		if (g_str_equal(p_ifname, WIFI_IFNAME) != TRUE)
			continue;

		/* read wireless status */
		p_entry = strtok(p_entry, " .");	// status			"%x"
		sscanf(p_entry, "%x", &status);
		p_entry = strtok(NULL, " .");		// Quality link		"%d"
		sscanf(p_entry, "%d", &link);
		p_entry = strtok(NULL, " .");		// Quality level	"%d"
		sscanf(p_entry, "%d", &rssi_dbm);
		p_entry = strtok(NULL, " .");		// Quality noise	"%d"
		sscanf(p_entry, "%d", &noise);

		/* No need to read */
		/*
		p_entry = strtok(NULL, " .");		// Discarded nwid	"%lu"
		sscanf(p_entry, "%lu", &nwid);
		p_entry = strtok(NULL, " .");		// Discarded crypt	"%lu"
		sscanf(p_entry, "%lu", &crypt);
		p_entry = strtok(NULL, " .");		// Discarded frag	"%lu"
		sscanf(p_entry, "%lu", &frag);
		p_entry = strtok(NULL, " .");		// Discarded retry	"%lu"
		sscanf(p_entry, "%lu", &retry);
		p_entry = strtok(NULL, " .");		// Discarded misc	"%lu"
		sscanf(p_entry, "%lu", &misc);
		p_entry = strtok(NULL, " .");		// Discarded missed	"%lu"
		sscanf(p_entry, "%lu", &missed);
		*/

		break;
	}

endline:
	fclose(fp);
	netconfig_wifi_rssi = rssi_dbm;

	return rssi_dbm;
}

int netconfig_wifi_rssi_level(const int rssi_dbm)
{
	int snr_level = 0;

	/* Wi-Fi Signal Strength Display
	 *
	 * Excellent :	-63 ~
	 * Good:		-74 ~ -64
	 * Weak:		-82 ~ -75
	 * Very weak:		~ -83
	 */
	if (rssi_dbm >= -63)
		snr_level = 4;
	else if (rssi_dbm >= -74)
		snr_level = 3;
	else if (rssi_dbm >= -82)
		snr_level = 2;
	else
		snr_level = 1;

	return snr_level;
}

static void __netconfig_wifi_set_rssi_level(const int snr_level)
{
	static int last_snr_level = 0;

	if (snr_level != last_snr_level) {
		netconfig_set_vconf_int(VCONFKEY_WIFI_STRENGTH, snr_level);
		last_snr_level = snr_level;
	}
}

static void __netconfig_wifi_data_activity_booster(int level)
{
	gboolean reply = FALSE;
	char level1[] = "int32:1";
	char level2[] = "int32:2";
	char level3[] = "int32:3";

	char lock[] = "int32:2000";
	char unlock[] = "int32:0";

	char *param_array[] = { NULL, NULL, NULL };
	static int booster_level = 0;

	if (level < 0 || booster_level == level)
		return;

	if (level > 0) {
		/* enable booster */
		switch(level) {
		case 1:
			param_array[0] = level1;
			break;
		case 2:
			param_array[0] = level2;
			break;
		case 3:
			param_array[0] = level3;
			break;
		default:
			ERR("Invalid level");
			return;
		}
		param_array[1] = lock;

		reply = netconfig_invoke_dbus_method_nonblock(
				"org.tizen.system.deviced",
				"/Org/Tizen/System/DeviceD/PmQos",
				"org.tizen.system.deviced.PmQos",
				"WifiThroughput",
				param_array,
				NULL);
		if (reply != TRUE)
			return;
	}

	/* disable previous booster */
	if (booster_level == 0)
		return;

	switch(booster_level) {
	case 1:
		param_array[0] = level1;
		break;
	case 2:
		param_array[0] = level2;
		break;
	case 3:
		param_array[0] = level3;
		break;
	default:
		ERR("Invalid level");
		return;
	}
	param_array[1] = unlock;

	reply = netconfig_invoke_dbus_method_nonblock(
			"org.tizen.system.deviced",
			"/Org/Tizen/System/DeviceD/PmQos",
			"org.tizen.system.deviced.PmQos",
			"WifiThroughput",
			param_array,
			NULL);
	if (reply != TRUE)
		return;

	booster_level = level;
}

static void __netconfig_wifi_update_indicator(void)
{
	static int last_transfer_state = 0;
	static guint64 netconfig_wifi_tx_bytes = 0;
	static guint64 netconfig_wifi_rx_bytes = 0;
	static int booster_tic = 0;
	static int old_level = 0;
	int booster_level = 0;
	guint64 tx, rx, tx_diff, rx_diff;
	int transfer_state;

	if (netconfig_wifi_get_bytes_statistics(&tx, &rx) == TRUE) {
		tx_diff = tx - netconfig_wifi_tx_bytes;
		rx_diff = rx - netconfig_wifi_rx_bytes;

		if (tx_diff > 0) {
			if (rx_diff > 0)
				transfer_state = VCONFKEY_WIFI_TRANSFER_STATE_TXRX;
			else
				transfer_state = VCONFKEY_WIFI_TRANSFER_STATE_TX;
		} else {
			if (rx_diff > 0)
				transfer_state = VCONFKEY_WIFI_TRANSFER_STATE_RX;
			else
				transfer_state = VCONFKEY_WIFI_TRANSFER_STATE_NONE;
		}

		if (transfer_state != last_transfer_state) {
			netconfig_set_vconf_int(VCONFKEY_WIFI_TRANSFER_STATE,
										transfer_state);
			last_transfer_state = transfer_state;
		}

		/* NETCONFIG_WIFI_DATA_ACTIVITY_BOOSTER */
		if (tx_diff >= NETCONFIG_WIFI_DATA_ACTIVITY_BOOSTER_LEVEL1 ||
			rx_diff >= NETCONFIG_WIFI_DATA_ACTIVITY_BOOSTER_LEVEL1)
			booster_level = 1;
		else if (tx_diff >= NETCONFIG_WIFI_DATA_ACTIVITY_BOOSTER_LEVEL2 ||
				rx_diff >= NETCONFIG_WIFI_DATA_ACTIVITY_BOOSTER_LEVEL2)
			booster_level = 2;
		else if (tx_diff >= NETCONFIG_WIFI_DATA_ACTIVITY_BOOSTER_LEVEL3 ||
				rx_diff >= NETCONFIG_WIFI_DATA_ACTIVITY_BOOSTER_LEVEL3)
			booster_level = 3;

		if (old_level == booster_level) {
			if (--booster_tic <= 0) {
				__netconfig_wifi_data_activity_booster(0);

				if (booster_level > 0) {
					__netconfig_wifi_data_activity_booster(booster_level);

					booster_tic = 2;
				}
			}
		} else {
			__netconfig_wifi_data_activity_booster(booster_level);

			if (booster_level > 0)
				booster_tic = 2;
			else
				booster_tic = 0;
		}

		if (booster_tic < 0)
			booster_tic = 0;

		old_level = booster_level;

		netconfig_wifi_tx_bytes = tx;
		netconfig_wifi_rx_bytes = rx;
	}
}

static gboolean __netconfig_wifi_indicator_monitor(gpointer data)
{
	int rssi_dbm = 0;
	int snr_level = 0;
	int pm_state = VCONFKEY_PM_STATE_NORMAL;

	if (netconfig_wifi_state_get_service_state() != NETCONFIG_WIFI_CONNECTED)
		return FALSE;

	/* In case of LCD off, we don't need to update Wi-Fi indicator */
	vconf_get_int(VCONFKEY_PM_STATE, &pm_state);
	if (pm_state >= VCONFKEY_PM_STATE_LCDOFF)
		return TRUE;

	rssi_dbm = __netconfig_wifi_update_and_get_rssi();
	snr_level = netconfig_wifi_rssi_level(rssi_dbm);
	__netconfig_wifi_set_rssi_level(snr_level);

	__netconfig_wifi_update_indicator();

	return TRUE;
}

void netconfig_wifi_indicator_start(void)
{
	INFO("Start Wi-Fi indicator");

	netconfig_set_vconf_int(VCONFKEY_WIFI_STRENGTH, VCONFKEY_WIFI_STRENGTH_MAX);

	netconfig_start_timer_seconds(
			NETCONFIG_WIFI_INDICATOR_INTERVAL,
			__netconfig_wifi_indicator_monitor,
			NULL,
			&netconfig_wifi_indicator_timer);
}

void netconfig_wifi_indicator_stop(void)
{
	INFO("Stop Wi-Fi indicator");

	netconfig_stop_timer(&netconfig_wifi_indicator_timer);

	netconfig_wifi_rssi = VCONFKEY_WIFI_SNR_MIN;
}
