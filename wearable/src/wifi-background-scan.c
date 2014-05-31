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
#include <vconf.h>
#include <vconf-keys.h>

#include "log.h"
#include "util.h"
#include "netdbus.h"
#include "wifi-state.h"
#include "wifi-background-scan.h"

#define SCAN_PERIODIC_DELAY		10
#define SCAN_EXPONENTIAL_MIN	4
#define SCAN_EXPONENTIAL_MAX	128

enum {
	WIFI_BGSCAN_MODE_EXPONENTIAL = 0x00,
	WIFI_BGSCAN_MODE_PERIODIC,
	WIFI_BGSCAN_MODE_MAX,
};

struct bgscan_timer_data {
	guint time;
	guint mode;
	guint timer_id;
};

static gboolean netconfig_wifi_scanning = FALSE;

static struct bgscan_timer_data *__netconfig_wifi_bgscan_get_bgscan_data(void)
{
	static struct bgscan_timer_data timer_data =
					{SCAN_EXPONENTIAL_MIN, WIFI_BGSCAN_MODE_EXPONENTIAL, 0};

	return &timer_data;
}

static guint __netconfig_wifi_bgscan_mode(gboolean is_set_mode, guint mode)
{
	static guint bgscan_mode = WIFI_BGSCAN_MODE_EXPONENTIAL;

	if (is_set_mode != TRUE)
		return bgscan_mode;

	if (mode < WIFI_BGSCAN_MODE_MAX)
		bgscan_mode = mode;

	DBG("Wi-Fi background scan mode set %d", bgscan_mode);

	return bgscan_mode;
}

static void __netconfig_wifi_bgscan_set_mode(guint mode)
{
	__netconfig_wifi_bgscan_mode(TRUE, mode);
}

static guint __netconfig_wifi_bgscan_get_mode(void)
{
	return __netconfig_wifi_bgscan_mode(FALSE, -1);
}

static gboolean __netconfig_wifi_bgscan_request_connman_scan(void)
{
	gboolean reply;

	if (netconfig_wifi_state_get_service_state() == NETCONFIG_WIFI_CONNECTED)
		if (__netconfig_wifi_bgscan_get_mode() == WIFI_BGSCAN_MODE_EXPONENTIAL)
			return TRUE;

	if (netconfig_wifi_state_get_service_state() == NETCONFIG_WIFI_CONNECTING)
		return FALSE;

	netconfig_wifi_set_scanning(TRUE);

	reply = netconfig_invoke_dbus_method_nonblock(CONNMAN_SERVICE,
			CONNMAN_WIFI_TECHNOLOGY_PREFIX,
			CONNMAN_TECHNOLOGY_INTERFACE, "Scan", NULL, NULL);
	if (reply != TRUE)
		netconfig_wifi_set_scanning(FALSE);

	return reply;
}

static gboolean __netconfig_wifi_bgscan_next_scan(gpointer data);

static gboolean __netconfig_wifi_bgscan_immediate_scan(gpointer data)
{
	static int retry = 0;

	if (__netconfig_wifi_bgscan_request_connman_scan() == TRUE) {
		retry = 0;
		return FALSE;
	} else if (retry >= 3) {
		retry = 0;
		return FALSE;
	}

	retry++;

	return TRUE;
}

static void __netconfig_wifi_bgscan_start_timer(struct bgscan_timer_data *data)
{
	if (data == NULL)
		return;

	netconfig_stop_timer(&(data->timer_id));

	data->mode = __netconfig_wifi_bgscan_get_mode();

	if (data->time < SCAN_EXPONENTIAL_MIN)
		data->time = SCAN_EXPONENTIAL_MIN;

	switch (data->mode) {
	case WIFI_BGSCAN_MODE_EXPONENTIAL:
		if ((data->time * 2) > SCAN_EXPONENTIAL_MAX)
			data->time = SCAN_EXPONENTIAL_MAX;
		else
			data->time = data->time * 2;

		break;
	case WIFI_BGSCAN_MODE_PERIODIC:
		if ((data->time * 2) > SCAN_PERIODIC_DELAY)
			data->time = SCAN_PERIODIC_DELAY;
		else
			data->time = data->time * 2;

		break;
	default:
		DBG("Error! Wi-Fi background scan mode [%d]", data->mode);
		return;
	}

	g_timeout_add(500, __netconfig_wifi_bgscan_immediate_scan, NULL);

	netconfig_start_timer_seconds(data->time,
			__netconfig_wifi_bgscan_next_scan, data, &(data->timer_id));
}

static void __netconfig_wifi_bgscan_stop_timer(struct bgscan_timer_data *data)
{
	if (data == NULL)
		return;

	netconfig_stop_timer(&(data->timer_id));
}

static gboolean __netconfig_wifi_bgscan_next_scan(gpointer data)
{
	struct bgscan_timer_data *timer = (struct bgscan_timer_data *)data;
	int pm_state = VCONFKEY_PM_STATE_NORMAL;

	if (timer == NULL)
		return FALSE;

	/* In case of LCD off, we don't need Wi-Fi scan */
	vconf_get_int(VCONFKEY_PM_STATE, &pm_state);
	if (pm_state >= VCONFKEY_PM_STATE_LCDOFF)
		return TRUE;

	__netconfig_wifi_bgscan_start_timer(timer);

	return FALSE;
}

void netconfig_wifi_bgscan_start(void)
{
	enum netconfig_wifi_tech_state wifi_tech_state;
	struct bgscan_timer_data *timer_data =
			__netconfig_wifi_bgscan_get_bgscan_data();

	if (timer_data == NULL)
		return;

	wifi_tech_state = netconfig_wifi_state_get_technology_state();
	if (wifi_tech_state < NETCONFIG_WIFI_TECH_POWERED)
		return;

	DBG("Wi-Fi background scan start or re-started");

	__netconfig_wifi_bgscan_start_timer(timer_data);
}

void netconfig_wifi_bgscan_stop(void)
{
	struct bgscan_timer_data *timer_data =
			__netconfig_wifi_bgscan_get_bgscan_data();

	if (timer_data == NULL)
		return;

	DBG("Wi-Fi background scan stop");

	timer_data->time = SCAN_EXPONENTIAL_MIN;

	__netconfig_wifi_bgscan_stop_timer(timer_data);
}

gboolean netconfig_wifi_get_bgscan_state(void)
{
	struct bgscan_timer_data *timer_data =
			__netconfig_wifi_bgscan_get_bgscan_data();

	return ((timer_data->timer_id > (guint)0) ? TRUE : FALSE);
}

gboolean netconfig_wifi_get_scanning(void)
{
	return netconfig_wifi_scanning;
}

void netconfig_wifi_set_scanning(gboolean scanning)
{
	if (netconfig_wifi_scanning != scanning)
		netconfig_wifi_scanning = scanning;
}

gboolean netconfig_iface_wifi_set_bgscan(
		NetconfigWifi *wifi, guint scan_mode, GError **error)
{
	__netconfig_wifi_bgscan_set_mode(scan_mode);

	netconfig_wifi_bgscan_stop();
	netconfig_wifi_bgscan_start();

	return TRUE;
}
