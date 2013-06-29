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
#include "network-statistics.h"
#include "netsupplicant.h"
#include "wifi-indicator.h"

#define VCONFKEY_WIFI_SNR_MIN	-89

#define NETCONFIG_WIFI_INDICATOR_INTERVAL	1

static guint64 netconfig_wifi_tx_bytes = 0;
static guint64 netconfig_wifi_rx_bytes = 0;

static guint netconfig_wifi_indicator_timer = 0;

#if defined NL80211
static int __netconfig_wifi_get_signal(const char *object_path)
{
	DBusConnection *connection = NULL;
	DBusMessage *message = NULL;
	DBusMessageIter iter;
	int rssi_dbm = 0;
	int MessageType = 0;

	if (object_path == NULL) {
		ERR("Error!!! path is NULL");
		goto error;
	}

	connection = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (connection == NULL) {
		ERR("Error!!! Failed to get system DBus");
		goto error;
	}

	message = netconfig_supplicant_invoke_dbus_method(
			SUPPLICANT_SERVICE, connection, object_path,
			SUPPLICANT_INTERFACE ".Interface", "GetLinkSignal",
			NULL);

	if (message == NULL) {
		ERR("Error!!! Failed to get service properties");
		goto error;
	}

	MessageType = dbus_message_get_type(message);

	if (MessageType == DBUS_MESSAGE_TYPE_ERROR) {
		const char *err_msg = dbus_message_get_error_name(message);
		ERR("Error!!! Error message received [%s]", err_msg);
		goto error;
	}

	dbus_message_iter_init(message, &iter);

	if ((MessageType = dbus_message_iter_get_arg_type(&iter)) == DBUS_TYPE_INT32)
		dbus_message_iter_get_basic(&iter, &rssi_dbm);
	else
		goto error;

	dbus_message_unref(message);
	dbus_connection_unref(connection);

	return rssi_dbm;

error:
	if (message != NULL)
		dbus_message_unref(message);

	if (connection != NULL)
		dbus_connection_unref(connection);

	return VCONFKEY_WIFI_SNR_MIN;
}

static int __netconfig_wifi_get_rssi_from_supplicant(void)
{
	int rssi_dbm =0;

	char object_path[DBUS_PATH_MAX_BUFLEN] = { 0, };
	char *path_ptr = &object_path[0];

	if (netconfig_wifi_get_supplicant_interface(&path_ptr) != TRUE) {
		DBG("Fail to get wpa_supplicant DBus path");
		return VCONFKEY_WIFI_SNR_MIN;
	}

	rssi_dbm = __netconfig_wifi_get_signal((const char *)path_ptr);

	return rssi_dbm;
}
#endif /* #if defined NL80211 */

#if !defined NL80211
static int __netconfig_wifi_get_rssi_from_system(void)
{
	int rssi_dbm = 0;
	char ifname[16] = { 0, };
	char *ifname_ptr = &ifname[0];

	int fd = -1;
	struct iwreq wifi_req;
	struct iw_statistics stats;
	unsigned int iw_stats_len = sizeof(struct iw_statistics);

	if (netconfig_wifi_get_ifname(&ifname_ptr) != TRUE) {
		DBG("Fail to get Wi-Fi ifname from wpa_supplicant: %s", ifname_ptr);
		return VCONFKEY_WIFI_SNR_MIN;
	}

	/* Set device name */
	memset(wifi_req.ifr_name, 0, sizeof(wifi_req.ifr_name));
	strncpy(wifi_req.ifr_name, ifname, sizeof(wifi_req.ifr_name) - 1);
	wifi_req.ifr_name[sizeof(wifi_req.ifr_name) - 1] = '\0';

	wifi_req.u.data.pointer = (caddr_t) &stats;
	wifi_req.u.data.length = iw_stats_len;
	wifi_req.u.data.flags = 1;	/* Clear updated flag */

	if ((fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP)) < 0) {
		DBG("Fail to open socket to get rssi");
		return VCONFKEY_WIFI_SNR_MIN;
	}

	memset(&stats, 0, iw_stats_len);

	if (ioctl(fd, SIOCGIWSTATS, &wifi_req) < 0) {
		DBG("Fail to execute ioctl for SIOCGIWSTATS");
		close(fd);

		return VCONFKEY_WIFI_SNR_MIN;
	}
	close(fd);

	rssi_dbm = stats.qual.level - 255; /** signed integer, so 255 */

	return rssi_dbm;
}
#endif /* #if !defined NL80211 */

int netconfig_wifi_get_rssi(void)
{
	int rssi_dbm = 0;

	/* There are two ways to get Wi-Fi RSSI:
	 *  - WEXT interface, get DBus path of wpa_supplicant,
	 *  and get Wi-Fi interface name e.g. wlan0 from wpa_supplicant.
	 *  IOCTL with ifname will return RSSI dB.
	 *  - NL80211 interface, get DBus path of wpa_supplicant,
	 *  and get RSSI from wpa_supplicant directly.
	 *  However, in this case wpa_supplicant needs some modification
	 *  to get RSSI from DBus interface. */

#if defined NL80211
	rssi_dbm = __netconfig_wifi_get_rssi_from_supplicant();
#else
	rssi_dbm = __netconfig_wifi_get_rssi_from_system();
#endif

	return rssi_dbm;
}

static void __netconfig_wifi_set_rssi_level(int rssi_dbm)
{
	int snr_level = 0;
	static int last_snr_level = 0;

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

	if (snr_level != last_snr_level) {
		INFO("Wi-Fi RSSI: %d dB, %d level", rssi_dbm, snr_level);

		vconf_set_int(VCONFKEY_WIFI_STRENGTH, snr_level);

		last_snr_level = snr_level;
	}
}

static gboolean __netconfig_wifi_indicator_monitor(gpointer data)
{
	int rssi_dbm = 0;
	int pm_state = VCONFKEY_PM_STATE_NORMAL;
	guint64 tx = 0, rx = 0;

	/* In case of LCD off, we don't need to update Wi-Fi indicator */
	vconf_get_int(VCONFKEY_PM_STATE, &pm_state);
	if (pm_state >= VCONFKEY_PM_STATE_LCDOFF)
		return TRUE;

	rssi_dbm = netconfig_wifi_get_rssi();

	if (netconfig_wifi_get_bytes_statistics(&tx, &rx) == TRUE) {
		if (netconfig_wifi_tx_bytes < tx) {
			if (netconfig_wifi_rx_bytes < rx)
				vconf_set_int(VCONFKEY_WIFI_TRANSFER_STATE, VCONFKEY_WIFI_TRANSFER_STATE_TXRX);
			else
				vconf_set_int(VCONFKEY_WIFI_TRANSFER_STATE, VCONFKEY_WIFI_TRANSFER_STATE_TX);
		} else {
			if (netconfig_wifi_rx_bytes < rx)
				vconf_set_int(VCONFKEY_WIFI_TRANSFER_STATE, VCONFKEY_WIFI_TRANSFER_STATE_RX);
			else
				vconf_set_int(VCONFKEY_WIFI_TRANSFER_STATE, VCONFKEY_WIFI_TRANSFER_STATE_NONE);
		}

		netconfig_wifi_tx_bytes = tx;
		netconfig_wifi_rx_bytes = rx;
	}

	__netconfig_wifi_set_rssi_level(rssi_dbm);

	return TRUE;
}

void netconfig_wifi_indicator_start(void)
{
	guint64 tx = 0, rx = 0;

	INFO("Start Wi-Fi indicator");

	vconf_set_int(VCONFKEY_WIFI_STRENGTH, VCONFKEY_WIFI_STRENGTH_MAX);

	if (netconfig_wifi_get_bytes_statistics(&tx, &rx) == TRUE) {
		netconfig_wifi_tx_bytes = tx;
		netconfig_wifi_rx_bytes = rx;
	} else {
		netconfig_wifi_tx_bytes = 0;
		netconfig_wifi_rx_bytes = 0;
	}

	netconfig_start_timer_seconds(
			NETCONFIG_WIFI_INDICATOR_INTERVAL,
			__netconfig_wifi_indicator_monitor,
			NULL,
			&netconfig_wifi_indicator_timer);
}

void netconfig_wifi_indicator_stop(void)
{
	INFO("Stop Wi-Fi indicator");

	vconf_set_int(VCONFKEY_WIFI_STRENGTH, VCONFKEY_WIFI_STRENGTH_MAX);

	netconfig_stop_timer(&netconfig_wifi_indicator_timer);
}
