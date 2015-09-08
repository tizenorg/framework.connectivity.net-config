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

#include <errno.h>
#include <vconf.h>
#include <vconf-keys.h>

#include "log.h"
#include "util.h"
#include "netdbus.h"
#include "emulator.h"
#include "neterror.h"
#include "wifi-ccode.h"
#include "netsupplicant.h"
#include "wifi-firmware.h"
#include "network-statistics.h"

#define WLAN_DRIVER_SCRIPT			"/usr/bin/wlan.sh"
#define WLAN_P2P_IFACE_NAME			"p2p0"

static int __netconfig_sta_firmware_start(void)
{
	int rv = 0;
	const char *path = WLAN_DRIVER_SCRIPT;
	char *const args[] = { "/usr/bin/wlan.sh", "start", NULL };
	char *const envs[] = { NULL };

	rv = netconfig_execute_file(path, args, envs);
	if (rv < 0)
		return -EIO;

	/* Do CCODE initialization here */
	netconfig_wifi_ccode_init();

	DBG("Successfully loaded wireless device driver");
	return 0;
}

static int __netconfig_sta_firmware_stop(void)
{
	int rv = 0;
	const char *path = WLAN_DRIVER_SCRIPT;
	char *const args[] = { "/usr/bin/wlan.sh", "stop", NULL };
	char *const envs[] = { NULL };

	/* Update statistics before driver remove */
	netconfig_wifi_statistics_update_powered_off();

	rv = netconfig_execute_file(path, args, envs);
	if (rv < 0)
		return -EIO;

	DBG("Successfully removed wireless device driver");
	return 0;
}

static int __netconfig_p2p_firmware_start(void)
{
#if defined TIZEN_P2P_ENABLE
	int rv = 0;
	const char *path = WLAN_DRIVER_SCRIPT;
	char *const args[] = { "/usr/bin/wlan.sh", "p2p", NULL };
	char *const envs[] = { NULL };

	rv = netconfig_execute_file(path, args, envs);
	if (rv < 0)
		return -EIO;

	DBG("Successfully loaded p2p device driver");
	return 0;
#else
	return -ENODEV;
#endif
}

static int __netconfig_p2p_firmware_stop(void)
{
#if defined TIZEN_P2P_ENABLE
	int rv = 0;
	const char *path = WLAN_DRIVER_SCRIPT;
	char *const args[] = { "/usr/bin/wlan.sh", "stop", NULL };
	char *const envs[] = { NULL };

	rv = netconfig_execute_file(path, args, envs);
	if (rv < 0)
		return -EIO;

	DBG("Successfully removed p2p device driver");
	return 0;
#else
	return -ENODEV;
#endif
}

static int __netconfig_softap_firmware_start(void)
{
#if defined TIZEN_TETHERING_ENABLE
	int rv = 0;
	const char *path = WLAN_DRIVER_SCRIPT;
	char *const args[] = { "/usr/bin/wlan.sh", "softap", NULL };
	char *const envs[] = { NULL };

	rv = netconfig_execute_file(path, args, envs);
	if (rv < 0)
		return -EIO;

	DBG("Successfully loaded softap device driver");
	return 0;
#else
	return -ENODEV;
#endif
}

static int __netconfig_softap_firmware_stop(void)
{
#if defined TIZEN_TETHERING_ENABLE
	int rv = 0;
	const char *path = WLAN_DRIVER_SCRIPT;
	char *const args[] = { "/usr/bin/wlan.sh", "stop", NULL };
	char *const envs[] = { NULL };

	rv = netconfig_execute_file(path, args, envs);
	if (rv < 0)
		return -EIO;

	DBG("Successfully removed softap device driver");
	return 0;
#else
	return -ENODEV;
#endif
}

static int __netconfig_wifi_firmware_start(enum netconfig_wifi_firmware type)
{
	if (netconfig_emulator_is_emulated() == TRUE)
		return -EIO;

	switch (type) {
	case NETCONFIG_WIFI_STA:
		return __netconfig_sta_firmware_start();
	case NETCONFIG_WIFI_P2P:
		return __netconfig_p2p_firmware_start();
	case NETCONFIG_WIFI_SOFTAP:
		return __netconfig_softap_firmware_start();
	default:
		break;
	}

	return -ENXIO;
}

static int __netconfig_wifi_firmware_stop(enum netconfig_wifi_firmware type)
{
	if (netconfig_emulator_is_emulated() == TRUE)
		return -EIO;

	switch (type) {
	case NETCONFIG_WIFI_STA:
		return __netconfig_sta_firmware_stop();
	case NETCONFIG_WIFI_P2P:
		return __netconfig_p2p_firmware_stop();
	case NETCONFIG_WIFI_SOFTAP:
		return __netconfig_softap_firmware_stop();
	default:
		break;
	}

	return -ENXIO;
}

int netconfig_wifi_firmware(enum netconfig_wifi_firmware type, gboolean enable)
{
	int err;
	static enum netconfig_wifi_firmware current_driver = NETCONFIG_WIFI_OFF;
	enum netconfig_wifi_firmware alias = type;

#if defined WLAN_CONCURRENT_MODE
	int flight_mode = 0;

	if (type == NETCONFIG_WIFI_P2P)
		alias = NETCONFIG_WIFI_STA;
#endif

	DBG("Wi-Fi current firmware %d (type: %d %s)", current_driver, type,
							enable == TRUE ? "enable" : "disable");

	if (enable == FALSE) {
		if (current_driver == NETCONFIG_WIFI_OFF) {
			return -EALREADY;
		} else if (current_driver == alias) {

#if defined WLAN_CONCURRENT_MODE
			vconf_get_bool(VCONFKEY_TELEPHONY_FLIGHT_MODE, &flight_mode);

			if (flight_mode == 0 && type == NETCONFIG_WIFI_STA &&
					netconfig_is_wifi_direct_on() == TRUE) {
				netconfig_interface_down(WIFI_IFNAME);

				return -EALREADY;
			}

			if (type == NETCONFIG_WIFI_P2P &&
					netconfig_wifi_state_get_technology_state() >
						NETCONFIG_WIFI_TECH_OFF) {
				netconfig_interface_down(WLAN_P2P_IFACE_NAME);

				return -EALREADY;
			}
#endif
			err = __netconfig_wifi_firmware_stop(type);
			if (err < 0 && err != -EALREADY)
				return err;

			current_driver = NETCONFIG_WIFI_OFF;

			return err;
		}

		return -EIO;
	}

	if (current_driver > NETCONFIG_WIFI_OFF) {
		if (current_driver == alias) {

#if defined WLAN_CONCURRENT_MODE
			if (type == NETCONFIG_WIFI_STA)
				netconfig_interface_up(WIFI_IFNAME);
#if defined TIZEN_P2P_ENABLE
			else if (type == NETCONFIG_WIFI_P2P)
				netconfig_interface_up(WLAN_P2P_IFACE_NAME);
#endif
#endif
			return -EALREADY;
		}

		return -EIO;
	}

	err = __netconfig_wifi_firmware_start(type);
	if (err < 0)
		DBG("Failed to execute script file");
	else
		current_driver = alias;

	return err;
}

gboolean netconfig_iface_wifi_start(
		NetconfigWifi *wifi, gchar *device, GError **error)
{
	int err;

	g_return_val_if_fail(wifi != NULL, FALSE);

	DBG("Wi-Fi firmware start %s", device != NULL ? device : "null");

	if (g_strcmp0("p2p", device) == 0)
		err = netconfig_wifi_firmware(NETCONFIG_WIFI_P2P, TRUE);
	else if (g_strcmp0("softap", device) == 0)
		err = netconfig_wifi_firmware(NETCONFIG_WIFI_SOFTAP, TRUE);
	else
		err = -EINVAL;

	if (err < 0) {
		if (err == -EALREADY)
			netconfig_error_already_exists(error);
		else
			netconfig_error_wifi_driver_failed(error);

		return FALSE;
	}

	return TRUE;
}

gboolean netconfig_iface_wifi_stop(
		NetconfigWifi *wifi, gchar *device, GError **error)
{
	int err;

	g_return_val_if_fail(wifi != NULL, FALSE);

	DBG("Wi-Fi firmware stop %s", device != NULL ? device : "null");

	if (g_strcmp0("p2p", device) == 0)
		err = netconfig_wifi_firmware(NETCONFIG_WIFI_P2P, FALSE);
	else if (g_strcmp0("softap", device) == 0)
		err = netconfig_wifi_firmware(NETCONFIG_WIFI_SOFTAP, FALSE);
	else
		err = -EINVAL;

	if (err < 0) {
		if (err == -EALREADY)
			netconfig_error_already_exists(error);
		else
			netconfig_error_wifi_driver_failed(error);

		return FALSE;
	}

	return TRUE;
}
