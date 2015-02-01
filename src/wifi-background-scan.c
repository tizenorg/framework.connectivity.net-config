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

#if defined TIZEN_WEARABLE
#define SCAN_PERIODIC_DELAY		15
#define SCAN_EXPONENTIAL_MIN	5
#define SCAN_EXPONENTIAL_MAX	320
#else
#define SCAN_PERIODIC_DELAY		10
#define SCAN_EXPONENTIAL_MIN	4
#define SCAN_EXPONENTIAL_MAX	128
#endif

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
static gboolean netconfig_bgscan_paused = FALSE;

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

static gboolean __netconfig_wifi_bgscan_request_connman_scan(int retries)
{
	gboolean reply;
	guint state = netconfig_wifi_state_get_service_state();

	if (state == NETCONFIG_WIFI_CONNECTED)
		if (__netconfig_wifi_bgscan_get_mode() == WIFI_BGSCAN_MODE_EXPONENTIAL)
			return TRUE;

	if (state == NETCONFIG_WIFI_ASSOCIATION ||state == NETCONFIG_WIFI_CONFIGURATION) {
		/* During Wi-Fi connecting, Wi-Fi can be disappeared.
		 * After 1 sec, try scan even if connecting state */
		if (retries < 2)
			return FALSE;
	}

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
	static int retries = 0;

#if !defined TIZEN_WEARABLE
	if (netconfig_wifi_is_bgscan_paused())
		return FALSE;
#endif

	if (__netconfig_wifi_bgscan_request_connman_scan(retries) == TRUE) {
		retries = 0;
		return FALSE;
	} else if (retries > 2) {
		retries = 0;
		return FALSE;
	}

	retries++;

	return TRUE;
}

static void __netconfig_wifi_bgscan_start_timer(gboolean immediate_scan,
		struct bgscan_timer_data *data)
{
	if (!data)
		return;

	netconfig_stop_timer(&(data->timer_id));

	data->mode = __netconfig_wifi_bgscan_get_mode();

	if (data->time < SCAN_EXPONENTIAL_MIN)
		data->time = SCAN_EXPONENTIAL_MIN;

	switch (data->mode) {
	case WIFI_BGSCAN_MODE_EXPONENTIAL:
		if (immediate_scan == TRUE) {
			if ((data->time * 2) > SCAN_EXPONENTIAL_MAX)
				data->time = SCAN_EXPONENTIAL_MAX;
			else
				data->time = data->time * 2;
		}

		break;
	case WIFI_BGSCAN_MODE_PERIODIC:
		if ((data->time * 2) > SCAN_PERIODIC_DELAY)
			data->time = SCAN_PERIODIC_DELAY;
		else
			data->time = data->time * 2;

		break;
	default:
		DBG("Invalid Wi-Fi background scan mode[%d]", data->mode);
		return;
	}

	if (immediate_scan == TRUE)
		g_timeout_add(500, __netconfig_wifi_bgscan_immediate_scan, NULL);

	DBG("Scan immediately[%d], mode[%d], next[%d]",
				immediate_scan, data->mode, data->time);

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

	__netconfig_wifi_bgscan_start_timer(TRUE, timer);

	return FALSE;
}

void netconfig_wifi_set_bgscan_pause(gboolean pause)
{
	DBG("[%s] Wi-Fi background scan", pause ? "Pause" : "Resume");
	netconfig_bgscan_paused = pause;
}

gboolean netconfig_wifi_is_bgscan_paused(void)
{
	DBG("Wi-Fi background scan is [%s]", netconfig_bgscan_paused ? "Paused" : "Runnable");
	return netconfig_bgscan_paused;
}

void netconfig_wifi_bgscan_start(gboolean immediate_scan)
{
	enum netconfig_wifi_tech_state wifi_tech_state;
	struct bgscan_timer_data *timer_data =
			__netconfig_wifi_bgscan_get_bgscan_data();

	if (timer_data == NULL)
		return;

	wifi_tech_state = netconfig_wifi_state_get_technology_state();
	if (wifi_tech_state < NETCONFIG_WIFI_TECH_POWERED)
		return;

	DBG("Wi-Fi background scan started or re-started(%d)", immediate_scan);

	__netconfig_wifi_bgscan_start_timer(immediate_scan, timer_data);
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
	gint old_mode = 0;
	int pm_state = VCONFKEY_PM_STATE_NORMAL;

	old_mode = __netconfig_wifi_bgscan_get_mode();
	if (old_mode == scan_mode)
		return TRUE;

	__netconfig_wifi_bgscan_set_mode(scan_mode);

	netconfig_wifi_bgscan_stop();

	/* In case of LCD off, we don't need Wi-Fi scan right now */
	vconf_get_int(VCONFKEY_PM_STATE, &pm_state);
	if (pm_state >= VCONFKEY_PM_STATE_LCDOFF)
		netconfig_wifi_bgscan_start(FALSE);
	else
		netconfig_wifi_bgscan_start(TRUE);

	return TRUE;
}

gboolean netconfig_iface_wifi_resume_bgscan(
		NetconfigWifi *wifi, GError **error)
{
	netconfig_wifi_set_bgscan_pause(FALSE);

	return TRUE;
}

gboolean netconfig_iface_wifi_pause_bgscan(
		NetconfigWifi *wifi, GError **error)
{
	netconfig_wifi_set_bgscan_pause(TRUE);

	return TRUE;
}

