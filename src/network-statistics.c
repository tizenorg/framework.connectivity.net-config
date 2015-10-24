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
#include <vconf.h>
#include <vconf-keys.h>

#include "log.h"
#include "util.h"
#include "netsupplicant.h"
#include "network-statistics.h"

#include "generated-code.h"

#define NETCONFIG_PROCDEV					"/proc/net/dev"

static Network_statistics *netconfigstatistics = NULL;

gboolean netconfig_wifi_get_bytes_statistics(guint64 *tx, guint64 *rx)
{
	gboolean ret = FALSE;
	FILE *fp;
	gchar buf[1024];
	gchar *p_ifname = NULL, *p_entry = NULL;

	*tx = 0;
	*rx = 0;

	fp = fopen(NETCONFIG_PROCDEV, "r");
	if (fp == NULL) {
		ERR("Failed to open %s", NETCONFIG_PROCDEV);
		return FALSE;
	}

	/* skip the first and second line */
	if (fgets(buf, sizeof(buf), fp) == NULL ||
			fgets(buf, sizeof(buf), fp) == NULL)
		goto endline;

	while (fgets(buf, sizeof(buf), fp)) {
		guint64 llval;
		gulong lval;

		p_ifname = buf;
		while (*p_ifname == ' ') p_ifname++;
		p_entry = strchr(p_ifname, ':');
		if (p_entry != NULL) {
			*p_entry++ = '\0';

		if (g_strcmp0(p_ifname, WIFI_IFNAME) != 0)
			continue;

		/* read interface statistics */
		sscanf(p_entry,
				"%llu %llu %lu %lu %lu %lu %lu %lu "
				"%llu %llu %lu %lu %lu %lu %lu %lu",
				rx,			/* rx bytes */
				&llval,		/* rx packet */
				&lval,		/* rx errors */
				&lval,		/* rx dropped */
				&lval,		/* rx fifo errors */
				&lval,		/* rx frame errors */
				&lval,		/* rx compressed */
				&lval,		/* rx multicast */

				tx,			/* tx bytes */
				&llval,		/* tx packet */
				&lval,		/* tx errors */
				&lval,		/* tx dropped */
				&lval,		/* tx fifo errors */
				&lval,		/* collisions */
				&lval,		/* tx carrier errors */
				&lval		/* tx compressed */
				);
		} else {
			ERR("No matched Iface name in proc file");
		}
		ret = TRUE;
		break;
	}

endline:
	fclose(fp);
	return ret;
}

static gboolean handle_get_wifi_total_tx_bytes(
		Network_statistics *object,
		GDBusMethodInvocation *context)
{
	guint64 tx = 0, rx = 0;
	guint64 tx_bytes = 0;
	guint64 total_bytes = 0;
	int val = 0;

	vconf_get_int(VCONFKEY_NETWORK_WIFI_PKT_TOTAL_SNT, &val);
	tx_bytes = (guint64)val;

	if (netconfig_wifi_get_bytes_statistics(&tx, &rx) == TRUE)
		total_bytes = tx + tx_bytes;
	else
		total_bytes = tx_bytes;

	network_statistics_complete_get_wifi_total_tx_bytes(object, context, total_bytes);
	return TRUE;
}

static gboolean handle_get_wifi_total_rx_bytes(
		Network_statistics *object,
		GDBusMethodInvocation *context)
{
	guint64 tx = 0, rx = 0;
	guint64 rx_bytes = 0;
	guint64 total_bytes = 0;
	int val = 0;

	vconf_get_int(VCONFKEY_NETWORK_WIFI_PKT_TOTAL_RCV, &val);
	rx_bytes = (guint64)val;

	if (netconfig_wifi_get_bytes_statistics(&tx, &rx) == TRUE)
		total_bytes = rx + rx_bytes;
	else
		total_bytes = rx_bytes;

	network_statistics_complete_get_wifi_total_rx_bytes(object, context, total_bytes);
	return TRUE;
}

static gboolean handle_get_wifi_last_tx_bytes(
		Network_statistics *object,
		GDBusMethodInvocation *context)
{
	guint64 tx = 0, rx = 0;
	guint64 tx_bytes = 0;
	guint64 last_bytes = 0;
	int val = 0;

	vconf_get_int(VCONFKEY_NETWORK_WIFI_PKT_LAST_SNT, &val);
	tx_bytes = (guint64)val;

	if (wifi_state_get_service_state() != NETCONFIG_WIFI_CONNECTED) {
		last_bytes = tx_bytes;
		network_statistics_complete_get_wifi_last_tx_bytes(object, context, last_bytes);
		return TRUE;
	}

	if (netconfig_wifi_get_bytes_statistics(&tx, &rx) == TRUE)
		last_bytes = tx < tx_bytes ? 0 : tx - tx_bytes;
	else
		last_bytes = tx_bytes;

	network_statistics_complete_get_wifi_last_tx_bytes(object, context, last_bytes);
	return TRUE;
}

static gboolean handle_get_wifi_last_rx_bytes(
		Network_statistics *object,
		GDBusMethodInvocation *context)
{
	guint64 tx = 0, rx = 0;
	guint64 rx_bytes = 0;
	guint64 last_bytes = 0;
	int val = 0;

	vconf_get_int(VCONFKEY_NETWORK_WIFI_PKT_LAST_RCV, &val);
	rx_bytes = (guint64)val;

	if (wifi_state_get_service_state() != NETCONFIG_WIFI_CONNECTED) {
		last_bytes = rx_bytes;
		network_statistics_complete_get_wifi_last_rx_bytes(object, context, last_bytes);
		return TRUE;
	}

	if (netconfig_wifi_get_bytes_statistics(&tx, &rx) == TRUE)
		last_bytes = rx < rx_bytes ? 0 : rx - rx_bytes;
	else
		last_bytes = rx_bytes;

	network_statistics_complete_get_wifi_last_rx_bytes(object, context, last_bytes);
	return TRUE;
}

static gboolean handle_reset_cellular_total_tx_bytes(
		Network_statistics *object,
		GDBusMethodInvocation *context)
{
	netconfig_set_vconf_int(VCONFKEY_NETWORK_CELLULAR_PKT_TOTAL_SNT, 0);
	network_statistics_complete_reset_cellular_total_tx_bytes(object, context);
	return TRUE;
}

static gboolean handle_reset_cellular_total_rx_bytes(
		Network_statistics *object,
		GDBusMethodInvocation *context)
{
	netconfig_set_vconf_int(VCONFKEY_NETWORK_CELLULAR_PKT_TOTAL_RCV, 0);
	network_statistics_complete_reset_cellular_total_rx_bytes(object, context);
	return TRUE;
}

static gboolean handle_reset_cellular_last_tx_bytes(
		Network_statistics *object,
		GDBusMethodInvocation *context)
{
	netconfig_set_vconf_int(VCONFKEY_NETWORK_CELLULAR_PKT_LAST_SNT, 0);
	network_statistics_complete_reset_cellular_last_tx_bytes(object, context);
	return TRUE;
}

static gboolean handle_reset_cellular_last_rx_bytes(
		Network_statistics *object,
		GDBusMethodInvocation *context)
{
	netconfig_set_vconf_int(VCONFKEY_NETWORK_CELLULAR_PKT_LAST_RCV, 0);
	network_statistics_complete_reset_cellular_last_rx_bytes(object, context);
	return TRUE;
}

static gboolean handle_reset_wifi_total_tx_bytes(
		Network_statistics *object,
		GDBusMethodInvocation *context)
{
	guint64 tx = 0, rx = 0;

	if (netconfig_wifi_get_bytes_statistics(&tx, &rx) == TRUE)
		netconfig_set_vconf_int(VCONFKEY_NETWORK_WIFI_PKT_TOTAL_SNT, -(int)tx);
	else
		netconfig_set_vconf_int(VCONFKEY_NETWORK_WIFI_PKT_TOTAL_SNT, 0);

	network_statistics_complete_reset_wifi_total_tx_bytes(object, context);

	return TRUE;
}

static gboolean handle_reset_wifi_total_rx_bytes(
		Network_statistics *object,
		GDBusMethodInvocation *context)
{
	guint64 tx = 0, rx = 0;

	if (netconfig_wifi_get_bytes_statistics(&tx, &rx) == TRUE)
		netconfig_set_vconf_int(VCONFKEY_NETWORK_WIFI_PKT_TOTAL_RCV, -(int)rx);
	else
		netconfig_set_vconf_int(VCONFKEY_NETWORK_WIFI_PKT_TOTAL_RCV, 0);

	network_statistics_complete_reset_wifi_total_rx_bytes(object, context);
	return TRUE;
}

static gboolean handle_reset_wifi_last_tx_bytes(
		Network_statistics *object,
		GDBusMethodInvocation *context)
{
	guint64 tx = 0, rx = 0;

	if (wifi_state_get_service_state() != NETCONFIG_WIFI_CONNECTED) {
		netconfig_set_vconf_int(VCONFKEY_NETWORK_WIFI_PKT_LAST_SNT, 0);
		network_statistics_complete_reset_wifi_last_tx_bytes(object, context);
		return TRUE;
	}

	if (netconfig_wifi_get_bytes_statistics(&tx, &rx) == TRUE)
		netconfig_set_vconf_int(VCONFKEY_NETWORK_WIFI_PKT_LAST_SNT, (int)tx);
	else
		netconfig_set_vconf_int(VCONFKEY_NETWORK_WIFI_PKT_LAST_SNT, 0);

	network_statistics_complete_reset_wifi_last_tx_bytes(object, context);

	return TRUE;
}

static gboolean handle_reset_wifi_last_rx_bytes(
		Network_statistics *object,
		GDBusMethodInvocation *context)
{
	guint64 tx = 0, rx = 0;

	if (wifi_state_get_service_state() != NETCONFIG_WIFI_CONNECTED) {
		netconfig_set_vconf_int(VCONFKEY_NETWORK_WIFI_PKT_LAST_RCV, 0);
		network_statistics_complete_reset_wifi_last_rx_bytes(object, context);
		return TRUE;
	}

	if (netconfig_wifi_get_bytes_statistics(&tx, &rx) == TRUE)
		netconfig_set_vconf_int(VCONFKEY_NETWORK_WIFI_PKT_LAST_RCV, (int)rx);
	else
		netconfig_set_vconf_int(VCONFKEY_NETWORK_WIFI_PKT_LAST_RCV, 0);

	network_statistics_complete_reset_wifi_last_rx_bytes(object, context);

	return TRUE;
}

void netconfig_wifi_statistics_update_powered_off(void)
{
	guint64 cur_tx = 0, cur_rx = 0;
	guint64 prev_tx = 0, prev_rx = 0;
	guint64 total_tx = 0, total_rx = 0;
	int val = 0;

	if (netconfig_wifi_get_bytes_statistics(&cur_tx, &cur_rx) != TRUE)
		return;

	vconf_get_int(VCONFKEY_NETWORK_WIFI_PKT_TOTAL_SNT, &val);
	prev_tx = (guint64)val;

	vconf_get_int(VCONFKEY_NETWORK_WIFI_PKT_TOTAL_RCV, &val);
	prev_rx = (guint64)val;

	total_tx = prev_tx + cur_tx;
	total_rx = prev_rx + cur_rx;

	netconfig_set_vconf_int(VCONFKEY_NETWORK_WIFI_PKT_TOTAL_SNT, (int)total_tx);
	netconfig_set_vconf_int(VCONFKEY_NETWORK_WIFI_PKT_TOTAL_RCV, (int)total_rx);
}

static void wifi_statistics_update_state(wifi_service_state_e state, void *user_data)
{
	guint64 tx = 0, rx = 0;
	guint64 last_tx = 0, last_rx = 0;
	int val = 0;
	static wifi_service_state_e prev_state = NETCONFIG_WIFI_UNKNOWN;

	if (prev_state == NETCONFIG_WIFI_UNKNOWN) {
		netconfig_set_vconf_int(VCONFKEY_NETWORK_WIFI_PKT_LAST_SNT, 0);
		netconfig_set_vconf_int(VCONFKEY_NETWORK_WIFI_PKT_LAST_RCV, 0);

		prev_state = NETCONFIG_WIFI_IDLE;
		return;
	}

	if (netconfig_wifi_get_bytes_statistics(&tx, &rx) != TRUE)
		return;

	if (state == NETCONFIG_WIFI_CONNECTED) {
		last_tx = tx;
		last_rx = rx;
	} else {
		if (prev_state != NETCONFIG_WIFI_CONNECTED)
			return;

		vconf_get_int(VCONFKEY_NETWORK_WIFI_PKT_LAST_SNT, &val);
		last_tx = (guint64)val;

		vconf_get_int(VCONFKEY_NETWORK_WIFI_PKT_LAST_RCV, &val);
		last_rx = (guint64)val;

		last_tx = tx < last_tx ? 0 : tx - last_tx;
		last_rx = rx < last_rx ? 0 : rx - last_rx;
	}

	netconfig_set_vconf_int(VCONFKEY_NETWORK_WIFI_PKT_LAST_SNT, (int)last_tx);
	netconfig_set_vconf_int(VCONFKEY_NETWORK_WIFI_PKT_LAST_RCV, (int)last_rx);

	prev_state = state;
}

static wifi_state_notifier state_notifier = {
		.wifi_state_changed = wifi_statistics_update_state,
		.user_data = NULL,
};

void statistics_object_create_and_init(void)
{
	DBG("Creating statistics object");
	GDBusInterfaceSkeleton *interface_statistics = NULL;
	GDBusConnection *connection = NULL;
	GDBusObjectManagerServer *server = netdbus_get_statistics_manager();
	if (server == NULL)
		return;

	connection = netdbus_get_connection();
	g_dbus_object_manager_server_set_connection(server, connection);

	/*Interface netconfig.network_statistics*/
	netconfigstatistics = network_statistics_skeleton_new();

	interface_statistics = G_DBUS_INTERFACE_SKELETON(netconfigstatistics);
	g_signal_connect(netconfigstatistics, "handle-get-wifi-last-rx-bytes",
				G_CALLBACK(handle_get_wifi_last_rx_bytes), NULL);
	g_signal_connect(netconfigstatistics, "handle-get-wifi-last-tx-bytes",
				G_CALLBACK(handle_get_wifi_last_tx_bytes), NULL);
	g_signal_connect(netconfigstatistics, "handle-get-wifi-total-rx-bytes",
				G_CALLBACK(handle_get_wifi_total_rx_bytes), NULL);
	g_signal_connect(netconfigstatistics, "handle-get-wifi-total-tx-bytes",
				G_CALLBACK(handle_get_wifi_total_tx_bytes), NULL);
	g_signal_connect(netconfigstatistics, "handle-reset-cellular-last-rx-bytes",
				G_CALLBACK(handle_reset_cellular_last_rx_bytes), NULL);
	g_signal_connect(netconfigstatistics, "handle-reset-cellular-last-tx-bytes",
				G_CALLBACK(handle_reset_cellular_last_tx_bytes), NULL);
	g_signal_connect(netconfigstatistics, "handle-reset-cellular-total-rx-bytes",
				G_CALLBACK(handle_reset_cellular_total_rx_bytes), NULL);
	g_signal_connect(netconfigstatistics, "handle-reset-cellular-total-tx-bytes",
				G_CALLBACK(handle_reset_cellular_total_tx_bytes), NULL);
	g_signal_connect(netconfigstatistics, "handle-reset-wifi-last-rx-bytes",
				G_CALLBACK(handle_reset_wifi_last_rx_bytes), NULL);
	g_signal_connect(netconfigstatistics, "handle-reset-wifi-last-tx-bytes",
				G_CALLBACK(handle_reset_wifi_last_tx_bytes), NULL);
	g_signal_connect(netconfigstatistics, "handle-reset-wifi-total-rx-bytes",
				G_CALLBACK(handle_reset_wifi_total_rx_bytes), NULL);
	g_signal_connect(netconfigstatistics, "handle-reset-wifi-total-tx-bytes",
				G_CALLBACK(handle_reset_wifi_total_tx_bytes), NULL);

	if (!g_dbus_interface_skeleton_export(interface_statistics, connection,
			NETCONFIG_NETWORK_STATISTICS_PATH, NULL)) {
		ERR("Export with path failed");
	}

	wifi_statistics_update_state(NETCONFIG_WIFI_IDLE, NULL);
	wifi_state_notifier_register(&state_notifier);

	return;
}

void statistics_object_deinit(void)
{
	g_object_unref(netconfigstatistics);
}
