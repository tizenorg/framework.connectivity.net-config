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

#include <glib.h>
#include <vconf.h>
#include <vconf-keys.h>

#include "log.h"
#include "util.h"
#include "wifi.h"
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
	static struct bgscan_timer_data timer_data = {SCAN_EXPONENTIAL_MIN, WIFI_BGSCAN_MODE_EXPONENTIAL, 0};

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
	DBusMessage *reply = NULL;

	if (netconfig_wifi_state_get_service_state() == NETCONFIG_WIFI_CONNECTED)
		if (__netconfig_wifi_bgscan_get_mode() == WIFI_BGSCAN_MODE_EXPONENTIAL)
			return FALSE;

	if (netconfig_wifi_state_get_service_state() == NETCONFIG_WIFI_CONNECTING)
		return FALSE;

	netconfig_wifi_set_scanning(TRUE);

		reply = netconfig_invoke_dbus_method(CONNMAN_SERVICE, CONNMAN_WIFI_TECHNOLOGY_PREFIX,
			CONNMAN_TECHNOLOGY_INTERFACE, "Scan", NULL);

	if (reply == NULL) {
		ERR("Error! Request failed");
		return FALSE;
	}

	dbus_message_unref(reply);

	return TRUE;
}

static gboolean __netconfig_wifi_bgscan_request_scan(gpointer data);

static void __netconfig_wifi_bgscan_start_timer(struct bgscan_timer_data *data)
{
	if (data == NULL)
		return;

	netconfig_stop_timer(&(data->timer_id));

	data->mode = __netconfig_wifi_bgscan_get_mode();

	switch (data->mode) {
	case WIFI_BGSCAN_MODE_EXPONENTIAL:
		if (data->time == 0)
			data->time = SCAN_EXPONENTIAL_MIN;
		else if ((data->time >= SCAN_EXPONENTIAL_MAX) ||
				(data->time > SCAN_EXPONENTIAL_MAX / 2))
			data->time = SCAN_EXPONENTIAL_MAX;
		else
			data->time = data->time * 2;

		break;
	case WIFI_BGSCAN_MODE_PERIODIC:
		data->time = SCAN_PERIODIC_DELAY;

		break;
	default:
		DBG("Error! Wi-Fi background scan mode [%d]", data->mode);
		return;
	}

	DBG("Register background scan timer with %d seconds", data->time);

	netconfig_start_timer_seconds(data->time,
			__netconfig_wifi_bgscan_request_scan, data, &(data->timer_id));
}

static void __netconfig_wifi_bgscan_stop_timer(struct bgscan_timer_data *data)
{
	if (data == NULL)
		return;

	netconfig_stop_timer(&(data->timer_id));
}

static gboolean __netconfig_wifi_bgscan_request_scan(gpointer data)
{
	struct bgscan_timer_data *timer = (struct bgscan_timer_data *)data;
	int pm_state = VCONFKEY_PM_STATE_NORMAL;

	if (timer == NULL)
		return FALSE;

	/* In case of LCD off, we don't need Wi-Fi scan */
	vconf_get_int(VCONFKEY_PM_STATE, &pm_state);
	if (pm_state >= VCONFKEY_PM_STATE_LCDOFF)
		return TRUE;

	__netconfig_wifi_bgscan_stop_timer(timer);

	DBG("Request Wi-Fi scan to ConnMan");
	__netconfig_wifi_bgscan_request_connman_scan();

	__netconfig_wifi_bgscan_start_timer(timer);

	return FALSE;
}

static void __netconfig_wifi_bgscan_mode_cb(keynode_t* node, void* user_data)
{
	int value;
	int wifi_state;

	if (vconf_get_int(VCONFKEY_WIFI_BGSCAN_MODE, &value) < 0) {
		ERR("VCONFKEY_WIFI_BGSCAN_MODE get failed");
		return;
	}

	DBG("Background scanning mode is changed : %d", value);

	__netconfig_wifi_bgscan_set_mode((guint)value);

	if (vconf_get_int(VCONFKEY_WIFI_STATE, &wifi_state) < 0) {
		ERR("VCONFKEY_WIFI_STATE get failed");
		return;
	}

	if (wifi_state == VCONFKEY_WIFI_OFF)
		return;

	struct bgscan_timer_data *timer_data = __netconfig_wifi_bgscan_get_bgscan_data();

	if (timer_data->timer_id != 0)
		netconfig_wifi_bgscan_stop();

	netconfig_wifi_bgscan_start();
}

void netconfig_wifi_bgscan_start(void)
{
	struct bgscan_timer_data *timer_data =
			__netconfig_wifi_bgscan_get_bgscan_data();

	if (timer_data == NULL)
		return;

	DBG("Wi-Fi background scan start");

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

gboolean netconfig_iface_wifi_set_bgscan(NetconfigWifi *wifi, guint scan_mode, GError **error)
{
	struct bgscan_timer_data *timer_data = __netconfig_wifi_bgscan_get_bgscan_data();

	__netconfig_wifi_bgscan_set_mode(scan_mode);

	if (timer_data->timer_id != 0)
		netconfig_wifi_bgscan_stop();

	netconfig_wifi_bgscan_start();

	return TRUE;
}

void netconfig_wifi_init_bgscan()
{
	guint scan_mode = __netconfig_wifi_bgscan_get_mode();

	if (scan_mode == WIFI_BGSCAN_MODE_PERIODIC)
		vconf_set_int(VCONFKEY_WIFI_BGSCAN_MODE, VCONFKEY_WIFI_BGSCAN_MODE_PERIODIC);
	else
		vconf_set_int(VCONFKEY_WIFI_BGSCAN_MODE, VCONFKEY_WIFI_BGSCAN_MODE_EXPONENTIAL);

	if (vconf_notify_key_changed(VCONFKEY_WIFI_BGSCAN_MODE,
			__netconfig_wifi_bgscan_mode_cb, NULL))
		DBG("Failed to set notify callback");
}

void netconfig_wifi_deinit_bgscan()
{
	if (vconf_ignore_key_changed(VCONFKEY_WIFI_BGSCAN_MODE,
			__netconfig_wifi_bgscan_mode_cb))
		DBG("Failed to unset notify callback");
}

