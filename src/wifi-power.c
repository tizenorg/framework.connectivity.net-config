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
#include <ITapiSim.h>
#include <TapiUtility.h>
#include <stdio.h>

#if defined TIZEN_P2P_ENABLE && !defined WLAN_CONCURRENT_MODE
#include <wifi-direct.h>
#endif

#include "log.h"
#include "util.h"
#include "netdbus.h"
#include "neterror.h"
#include "wifi-wps.h"
#include "wifi-power.h"
#include "wifi-state.h"
#include "wifi-tel-intf.h"
#include "netsupplicant.h"
#include "network-state.h"
#include "wifi-firmware.h"
#include "wifi-background-scan.h"


#define WLAN_SUPPLICANT_SCRIPT		"/usr/sbin/wpa_supp.sh"
#define P2P_SUPPLICANT_SCRIPT		"/usr/sbin/p2p_supp.sh"

#if defined TIZEN_WEARABLE
#include <weconn.h>
static weconn_h weconn_handle = NULL;
#endif

#define VCONF_WIFI_OFF_STATE_BY_AIRPLANE	"file/private/wifi/wifi_off_by_airplane"
#define VCONF_WIFI_OFF_STATE_BY_RESTRICTED	"file/private/wifi/wifi_off_by_restricted"
#define VCONF_WIFI_OFF_STATE_BY_EMERGENCY	"file/private/wifi/wifi_off_by_emergency"
#if defined TIZEN_WEARABLE
#define VCONF_WIFI_WEARABLE_WIFI_USE			"db/private/wifi/wearable_wifi_use"
#endif

#define WLAN_MAC_INFO		    "/opt/etc/.mac.info"
#define WLAN_MAC_ADDR_MAX	    20
#define VCONF_WIFI_BSSID_ADDRESS	"db/wifi/bssid_address"

#if defined TIZEN_TV
#define ETH_MAC_ADDR_SIZE 6
#define VCONF_ETH_MAC_ADDRESS  "db/dnet/mac_address"
#define NET_EXEC_PATH "/sbin/ifconfig"
#define OS_RANDOM_FILE "/dev/urandom"
#endif

static gboolean connman_wifi_technology_state = FALSE;
static gboolean wifi_firmware_recovery_mode = FALSE;
static int airplane_mode = 0;

#if defined TIZEN_WEARABLE
static int psmode_wifi_use = 1;
#endif

static gboolean __is_wifi_restricted(void)
{
#if defined TIZEN_WEARABLE
	return FALSE;
#endif
	int restricted_mode = 0;

	vconf_get_bool(VCONFKEY_SETAPPL_NETWORK_RESTRICT_MODE, &restricted_mode);
	if (restricted_mode != 0) {
		DBG("network restricted mode[%d]", restricted_mode);
		return TRUE;
	}

	return FALSE;
}

static void __technology_reply(GObject *source_object, GAsyncResult *res, gpointer user_data)
{
	GVariant *reply;
	GDBusConnection *conn = NULL;
	GError *error = NULL;

	conn = G_DBUS_CONNECTION (source_object);
	reply = g_dbus_connection_call_finish(conn, res, &error);

	if (reply == NULL) {
		if (error != NULL) {
			if (g_strcmp0(error->message, CONNMAN_ERROR_INTERFACE ".AlreadyEnabled") == 0) {
				wifi_state_update_power_state(TRUE);
			} else if (g_strcmp0(error->message, CONNMAN_ERROR_INTERFACE ".AlreadyDisabled") == 0) {
				wifi_state_update_power_state(FALSE);
			} else {
				ERR("Fail to request status [%d: %s]", error->code, error->message);
			}
			g_error_free(error);
		} else {
			ERR("Fail torequest status");
		}
	} else {
		DBG("Successfully requested");
	}

	g_variant_unref(reply);
	netconfig_gdbus_pending_call_unref();
}

static int __execute_supplicant(gboolean enable)
{
	int rv = 0;
	const char *path = WLAN_SUPPLICANT_SCRIPT;
	char *const args_enable[] = { "/usr/sbin/wpa_supp.sh", "start", NULL };
	char *const args_disable[] = { "/usr/sbin/wpa_supp.sh", "stop", NULL };
	char *const envs[] = { NULL };
	static gboolean enabled = FALSE;

	if (enabled == enable)
		return -EALREADY;

	if (enable == TRUE)
		rv = netconfig_execute_file(path, args_enable, envs);
	else
		rv = netconfig_execute_file(path, args_disable, envs);
	if (rv < 0)
		return -EIO;

	DBG("wpa_supplicant %s", enable == TRUE ? "started" : "stopped");

	enabled = enable;

	return 0;
}

static int _start_supplicant(void)
{
	GVariant *reply = NULL;
	GVariant *params = NULL;

	params = g_variant_new("(ss)","wpasupplicant.service", "replace");

	reply = netconfig_invoke_dbus_method("org.freedesktop.systemd1", "/org/freedesktop/systemd1", "org.freedesktop.systemd1.Manager", "StartUnit", params);
	if (reply == NULL) {
		ERR("Fail to _start_supplicant");
		return -1;
	} else {
		g_variant_unref(reply);
	}

	return 0;
}

static int _stop_supplicant(void)
{
	GVariant *reply = NULL;

	reply = netconfig_invoke_dbus_method("fi.w1.wpa_supplicant1", "/fi/w1/wpa_supplicant1", "fi.w1.wpa_supplicant1", "Terminate", NULL);
	if (reply == NULL) {
		ERR("Fail to _stop_supplicant");
		return -1;
	} else {
		g_variant_unref(reply);
	}

	return 0;
}

#if defined TIZEN_P2P_ENABLE && defined WLAN_CONCURRENT_MODE
static int __netconfig_p2p_supplicant(gboolean enable)
{
	int rv = 0;
	const char *path = P2P_SUPPLICANT_SCRIPT;
	char *const args_enable[] = { P2P_SUPPLICANT_SCRIPT, "start", NULL };
	char *const args_disable[] = { P2P_SUPPLICANT_SCRIPT, "stop", NULL };
	char *const envs[] = { NULL };

	if (enable == TRUE)
		rv = netconfig_execute_file(path, args_enable, envs);
	else
		rv = netconfig_execute_file(path, args_disable, envs);
	if (rv < 0)
		return -EIO;

	DBG("p2p_supplicant %s", enable == TRUE ? "started" : "stopped");

	return 0;
}
#endif

void netconfig_wifi_recover_firmware(void)
{
	wifi_firmware_recovery_mode = TRUE;

	netconfig_wifi_bgscan_stop();

	wifi_power_off();
}

#if defined TIZEN_P2P_ENABLE && !defined WLAN_CONCURRENT_MODE
static void __netconfig_wifi_direct_state_cb(int error_code, wifi_direct_device_state_e device_state, void *user_data)
{
	int err;

	wifi_direct_unset_device_state_changed_cb();
	wifi_direct_deinitialize();

	if (device_state == WIFI_DIRECT_DEVICE_STATE_DEACTIVATED) {
		err = wifi_power_on();
		if (err < 0) {
			if (err == -EALREADY)
				wifi_state_update_power_state(TRUE);
			else
				wifi_state_emit_power_failed();
		}
	}
}

static gboolean __netconfig_wifi_direct_power_off(void)
{
	DBG("Wi-Fi direct is turning off");

	if (wifi_direct_initialize() < 0)
		return FALSE;

	if (wifi_direct_set_device_state_changed_cb(__netconfig_wifi_direct_state_cb, NULL) < 0)
		return FALSE;

	if (wifi_direct_deactivate() < 0)
		return FALSE;

	return TRUE;
}
#endif

static int _load_driver_and_supplicant(void)
{
	int err = 0;
	wifi_tech_state_e tech_state;

	tech_state = wifi_state_get_technology_state();
	if (tech_state > NETCONFIG_WIFI_TECH_OFF)
		return -EALREADY;

	err = __execute_supplicant(TRUE);
	if (err < 0 && err != -EALREADY)
		return err;

	err = netconfig_wifi_firmware(NETCONFIG_WIFI_STA, TRUE);
	if (err < 0 && err != -EALREADY) {
		__execute_supplicant(FALSE);
		return err;
	}

	wifi_state_set_tech_state(NETCONFIG_WIFI_TECH_WPS_ONLY);

	return 0;
}

static int _remove_driver_and_supplicant(void)
{
	int err = 0;

	if (wifi_firmware_recovery_mode != TRUE &&
					netconfig_wifi_is_wps_enabled() == TRUE) {
		DBG("Wi-Fi WPS mode");
		return 0;
	}

	err = netconfig_wifi_firmware(NETCONFIG_WIFI_STA, FALSE);
	if (err < 0 && err != -EALREADY)
		return err;

	err = __execute_supplicant(FALSE);
	if (err < 0 && err != -EALREADY)
		return err;

	wifi_state_set_tech_state(NETCONFIG_WIFI_TECH_OFF);

	if (wifi_firmware_recovery_mode == TRUE) {
		if (wifi_power_on() < 0)
			ERR("Failed to recover Wi-Fi firmware");

		wifi_firmware_recovery_mode = FALSE;
	}

	return 0;
}

static int _set_connman_technology_power(gboolean enable)
{
	gboolean reply = FALSE;
	GVariant *param0 = NULL;
	GVariant *params = NULL;
	char key[] = "Powered";
	gboolean value_enable = TRUE;
	gboolean value_disable = FALSE;

	if (connman_wifi_technology_state == enable)
		return -EALREADY;

	if (enable == TRUE)
		param0 = g_variant_new_boolean(value_enable);
	else
		param0 = g_variant_new_boolean(value_disable);

	params = g_variant_new("(sv)",key, param0);

	reply = netconfig_invoke_dbus_method_nonblock(CONNMAN_SERVICE,
			CONNMAN_WIFI_TECHNOLOGY_PREFIX, CONNMAN_TECHNOLOGY_INTERFACE,
			"SetProperty", params, __technology_reply);

	if (reply != TRUE) {
		ERR("Fail to set technology %s", enable == TRUE ? "enable" : "disable");
		return -ESRCH;
	}

	/* If Wi-Fi powered off,
	 * Do not remove Wi-Fi driver until ConnMan technology state updated
	 */
	if (enable == TRUE)
		connman_wifi_technology_state = enable;

	/* To be keep safe, early disable Wi-Fi tech state */
	if (enable != TRUE)
		wifi_state_set_tech_state(NETCONFIG_WIFI_TECH_WPS_ONLY);

	return 0;
}

static void __netconfig_set_wifi_bssid(void)
{
	int rv = 0;
	char bssid[WLAN_MAC_ADDR_MAX];

	FILE *fp = fopen(WLAN_MAC_INFO, "r");

	if (fp == NULL) {
		ERR("Fail to open file");
		return;
	}

	fseek(fp, 0L, SEEK_SET);
	rv = fscanf(fp, "%s", bssid);

	if (rv < 0)
		ERR("Fail to read bssid");

	netconfig_set_vconf_str(VCONF_WIFI_BSSID_ADDRESS, bssid);

	fclose(fp);
}

int netconfig_wifi_driver_and_supplicant(gboolean enable)
{
	/* There are 3 thumb rules for Wi-Fi power management
	 *   1. Do not make exposed API to control wpa_supplicant and driver directly.
	 *      It probably breaks ConnMan technology operation.
	 *
	 *   2. Do not remove driver and wpa_supplicant if ConnMan already enabled.
	 *      It breaks ConnMan technology operation.
	 *
	 *   3. Final the best rule: make it as simple as possible.
	 *      Simple code enables easy maintenance and reduces logical errors.
	 */
	if (enable == TRUE)
		return _load_driver_and_supplicant();
	else {
		if (connman_wifi_technology_state == TRUE)
			return -ENOSYS;

		return _load_driver_and_supplicant();
	}
}

void netconfig_wifi_disable_technology_state_by_only_connman_signal(void)
{
	/* Important: it's only done by ConnMan technology signal update */
	connman_wifi_technology_state = FALSE;
}

int netconfig_wifi_on(void)
{
	int err = 0;
	wifi_tech_state_e wifi_tech_state;

	wifi_tech_state = wifi_state_get_technology_state();
	if (wifi_tech_state >= NETCONFIG_WIFI_TECH_POWERED)
		return -EALREADY;

	if (__is_wifi_restricted() == TRUE)
		return -EPERM;

	if (netconfig_is_wifi_tethering_on() == TRUE) {
		/* TODO: Wi-Fi tethering turns off here */
		/* return TRUE; */
		ERR("Failed to turn tethering off");
		return -EBUSY;
	}

#if defined TIZEN_P2P_ENABLE && !defined WLAN_CONCURRENT_MODE
	if (netconfig_is_wifi_direct_on() == TRUE) {
		if (__netconfig_wifi_direct_power_off() == TRUE)
			return -EINPROGRESS;
		else {
			ERR("Failed to turn Wi-Fi direct off");
			return -EBUSY;
		}
	}
#endif

	err = wifi_power_driver_and_supplicant(TRUE);
	if (err < 0 && err != -EALREADY)
		return err;

	err = _set_connman_technology_power(TRUE);

	__netconfig_set_wifi_bssid();

	return err;
}

int netconfig_wifi_off(void)
{
	int err;

#if defined TIZEN_P2P_ENABLE && defined WLAN_CONCURRENT_MODE
	__netconfig_p2p_supplicant(FALSE);
#endif

	err = _set_connman_technology_power(FALSE);
	if (err == -EALREADY)
		wifi_state_update_power_state(FALSE);

	return 0;
}

#if defined TIZEN_WEARABLE
int netconfig_wifi_on_wearable(gboolean device_picker_test)
{
	int err = 0;
	int wifi_use;
	int ps_mode;
	enum netconfig_wifi_tech_state wifi_tech_state;
	weconn_service_state_e weconn_state;

	wifi_tech_state = wifi_state_get_technology_state();
	if (wifi_tech_state >= NETCONFIG_WIFI_TECH_POWERED)
		return -EALREADY;

	err = weconn_get_service_state(weconn_handle, W_SERVICE_TYPE_BT,
			&weconn_state);
	if (err == 0 && weconn_state == W_SERVICE_STATE_CONNECTED) {
		WARN("Not permitted Wi-Fi on");
		return -EPERM;
	}

	if (vconf_get_int(VCONF_WIFI_WEARABLE_WIFI_USE, &wifi_use) < 0) {
		ERR("Fail to get VCONF_WIFI_WEARABLE_WIFI_USE");
		return -EIO;
	}

	if (wifi_use > 0) {
		if (vconf_get_int(VCONFKEY_SETAPPL_PSMODE, &ps_mode) < 0) {
			ERR("Fail to get VCONFKEY_SETAPPL_PSMODE");
			return -EIO;
		}

		if (ps_mode > SETTING_PSMODE_NORMAL) {
			WARN("ps mode is on(%d), Not turn on Wi-Fi", ps_mode);
			return -EPERM;
		}
	} else {
		WARN("Not permitted Wi-Fi on");
		return -EPERM;
	}

	err = wifi_power_driver_and_supplicant(TRUE);
	if (err < 0 && err != -EALREADY)
		return err;

	err = _set_connman_technology_power(TRUE);

	if (device_picker_test == TRUE)
		netconfig_wifi_enable_device_picker_test();

	return err;
}

static void __weconn_service_state_changed_cb(weconn_service_state_e state, void *user_data)
{
	if (state == W_SERVICE_STATE_CONNECTED) {
		DBG("SAP is connected");
		if (wifi_state > VCONFKEY_WIFI_OFF)
			wifi_power_off();
	} else if (state == W_SERVICE_STATE_DISCONNECTED) {
		DBG("SAP is disconnected");
		wifi_power_on_wearable(FALSE);
	}
}

static int _weconn_set_state_changed_cb(int service_type, void *user_data)
{
	int ret;

	if (weconn_handle) {
		weconn_destroy(weconn_handle);
		weconn_handle = NULL;
	}

	ret = weconn_create(&weconn_handle);
	if (ret < 0) {
		ERR("Failed weconn_create(%d)", ret);
		return -1;
	}

	ret = weconn_set_service_state_change_cb(weconn_handle, __weconn_service_state_changed_cb, service_type, user_data);
	if (ret < 0) {
		ERR("Failed weconn_set_service_state_change_cb(%d)", ret);
		return -1;
	}

	return 0;
}

static void __wearable_wifi_use_changed_cb(keynode_t* node, void* user_data)
{
	int wifi_state;
	int wifi_use = 1;
	gboolean wifi_restrict = FALSE;

	if (vconf_get_int(VCONFKEY_WIFI_STATE, &wifi_state) < 0) {
		ERR("Fail to get VCONFKEY_WIFI_STATE");
		return;
	}

	if (node != NULL)
		wifi_use = vconf_keynode_get_int(node);
	else
		vconf_get_int(VCONF_WIFI_WEARABLE_WIFI_USE, &wifi_use);

	if (wifi_use > 0) {
		DBG("wifi use on");
		if (wifi_state > VCONFKEY_WIFI_OFF) {
			WARN("Wi-Fi is already turned on");
			return;
		}

		wifi_restrict = netconfig_is_wifi_allowed();
		if (wifi_restrict == FALSE) {
			DBG("launch wifi restrict popup");
			netconfig_set_vconf_int(VCONF_WIFI_WEARABLE_WIFI_USE, 0);
			wc_launch_syspopup(WC_POPUP_TYPE_WIFI_RESTRICT);
		} else {
			wifi_power_on_wearable(TRUE);
		}
	} else {
		ERR("## wifi use [OFF]");
		if (wifi_state == VCONFKEY_WIFI_OFF) {
			WARN("Wi-Fi is already turned off");
			return;
		}

		wifi_power_off();
	}
}

#if defined TIZEN_TELEPHONY_ENABLE
static void __netconfig_wifi_wearable_airplane_mode(keynode_t *node,
		void *user_data)
{
	int wifi_use = 0, airplane_state = 0;
	int wifi_use_off_by_airplane = 0;

	vconf_get_int(VCONF_WIFI_OFF_STATE_BY_AIRPLANE,
			&wifi_use_off_by_airplane);

	vconf_get_int(VCONF_WIFI_WEARABLE_WIFI_USE, &wifi_use);

	if (node != NULL)
		airplane_state = vconf_keynode_get_bool(node);
	else
		vconf_get_bool(VCONFKEY_TELEPHONY_FLIGHT_MODE, &airplane_state);

	DBG("airplane mode %s (prev:%d)", airplane_state > 0 ? "ON" : "OFF", airplane_mode);
	DBG("Wi-Fi use %d, Wi-Fi was off by flight mode %s", wifi_use,
			wifi_use_off_by_airplane ? "Yes" : "No");

	if (airplane_mode == airplane_state)
		return ;

	airplane_mode = airplane_state;

	if (airplane_state > 0) {
		/* airplane mode on */
		if (wifi_use == 0)
			return;

		netconfig_set_vconf_int(VCONF_WIFI_OFF_STATE_BY_AIRPLANE, 1);
		netconfig_set_vconf_int(VCONF_WIFI_WEARABLE_WIFI_USE, 0);

	} else {
		/* airplane mode off */
		if (!wifi_use_off_by_airplane)
			return;

		netconfig_set_vconf_int(VCONF_WIFI_OFF_STATE_BY_AIRPLANE, 0);
		netconfig_set_vconf_int(VCONF_WIFI_WEARABLE_WIFI_USE, 1);
	}
}
#endif
#else
#if defined TIZEN_TELEPHONY_ENABLE
static void __netconfig_wifi_airplane_mode(keynode_t *node, void *user_data)
{
	int wifi_state = 0, airplane_state = 0;
	int wifi_off_by_airplane = 0;

	vconf_get_int(VCONF_WIFI_OFF_STATE_BY_AIRPLANE, &wifi_off_by_airplane);

	vconf_get_int(VCONFKEY_WIFI_STATE, &wifi_state);

	if (node != NULL)
		airplane_state = vconf_keynode_get_bool(node);
	else
		vconf_get_bool(VCONFKEY_TELEPHONY_FLIGHT_MODE, &airplane_state);

	DBG("airplane mode %s (prev:%d)", airplane_state > 0 ? "ON" : "OFF", airplane_mode);
	DBG("Wi-Fi state %d, Wi-Fi was off by flight mode %s", wifi_state,
			wifi_off_by_airplane ? "Yes" : "No");

	if (airplane_mode == airplane_state)
		return ;

	airplane_mode = airplane_state;

	if (airplane_state > 0) {
		/* airplane mode on */
		if (wifi_state == VCONFKEY_WIFI_OFF)
			return;

		wifi_power_off();

		netconfig_set_vconf_int(VCONF_WIFI_OFF_STATE_BY_AIRPLANE, 1);
	} else {
		/* airplane mode off */
		if (!wifi_off_by_airplane)
			return;

		netconfig_set_vconf_int(VCONF_WIFI_OFF_STATE_BY_AIRPLANE, 0);

		if (wifi_state > VCONFKEY_WIFI_OFF)
			return;

		wifi_power_on();
	}
}
#endif

static void __netconfig_wifi_restrict_mode(keynode_t *node, void *user_data)
{
	int wifi_state = 0, restricted = 0;
	int wifi_off_by_restricted = 0;

	vconf_get_int(VCONF_WIFI_OFF_STATE_BY_RESTRICTED, &wifi_off_by_restricted);

	vconf_get_int(VCONFKEY_WIFI_STATE, &wifi_state);

	if (node != NULL)
		restricted = vconf_keynode_get_bool(node);
	else
		vconf_get_bool(VCONFKEY_SETAPPL_NETWORK_RESTRICT_MODE, &restricted);

	DBG("network restricted mode %s", restricted > 0 ? "ON" : "OFF");
	DBG("Wi-Fi state %d, Wi-Fi was off by restricted mode %s", wifi_state,
			wifi_off_by_restricted ? "Yes" : "No");

	if (restricted > 0) {
		/* network restricted on */
		if (wifi_state == VCONFKEY_WIFI_OFF)
			return;

		wifi_power_off();

		netconfig_set_vconf_int(VCONF_WIFI_OFF_STATE_BY_RESTRICTED, 1);
	} else {
		/* network restricted off */
		if (!wifi_off_by_restricted)
			return;

		netconfig_set_vconf_int(VCONF_WIFI_OFF_STATE_BY_RESTRICTED, 0);

		if (wifi_state > VCONFKEY_WIFI_OFF)
			return;

		wifi_power_on();
	}
}
#endif

static void __emergency_mode_changed_cb(keynode_t *node, void *user_data)
{
	int wifi_state = 0, emergency = 0;
	int wifi_off_by_emergency = 0;
#if !defined TIZEN_WEARABLE
	int emergency_by_fmm = 0;
#endif
#if defined TIZEN_WEARABLE
	int wifi_use = 1;
#endif

	vconf_get_int(VCONF_WIFI_OFF_STATE_BY_EMERGENCY, &wifi_off_by_emergency);
	vconf_get_int(VCONFKEY_WIFI_STATE, &wifi_state);

#if !defined TIZEN_WEARABLE
	vconf_get_bool(VCONFKEY_SETAPPL_NETWORK_PERMIT_WITH_LCD_OFF_LIMIT, &emergency_by_fmm);
	DBG("emergency mode by Find My Mobile (%d)", emergency_by_fmm);
	if (emergency_by_fmm == 1)
		return;
#endif

	if (node != NULL)
		emergency = vconf_keynode_get_int(node);
	else
		vconf_get_int(VCONFKEY_SETAPPL_PSMODE, &emergency);

	DBG("emergency mode %s", emergency > SETTING_PSMODE_POWERFUL ? "ON" : "OFF");
	DBG("Wi-Fi state %d, Wi-Fi was off by emergency mode %s", wifi_state, wifi_off_by_emergency ? "Yes" : "No");

#if defined TIZEN_WEARABLE
	if (emergency == SETTING_PSMODE_WEARABLE) {
		/* basic power saving mode on */
	} else if (emergency == SETTING_PSMODE_WEARABLE_ENHANCED) {
		/* enhanced power saving mode on */
		vconf_get_int(VCONF_WIFI_WEARABLE_WIFI_USE, &wifi_use);
		psmode_wifi_use = wifi_use;
		if (wifi_use != 0) {
			netconfig_set_vconf_int(VCONF_WIFI_WEARABLE_WIFI_USE, 0);
		}

		if (wifi_state == VCONFKEY_WIFI_OFF)
			return;

		wifi_power_off();
		netconfig_set_vconf_int(VCONF_WIFI_OFF_STATE_BY_EMERGENCY, 1);
	} else {
		/* power saving mode off */
		netconfig_set_vconf_int(VCONF_WIFI_WEARABLE_WIFI_USE, psmode_wifi_use);
		if (!wifi_off_by_emergency)
			return;

		netconfig_set_vconf_int(VCONF_WIFI_OFF_STATE_BY_EMERGENCY, 0);
		if (wifi_state > VCONFKEY_WIFI_OFF)
			return;

		wifi_power_on_wearable(TRUE);
	}
#else
	if (emergency > SETTING_PSMODE_POWERFUL) {
		/* emergency mode on */
		if (wifi_state == VCONFKEY_WIFI_OFF)
			return;

		wifi_power_off();

		netconfig_set_vconf_int(VCONF_WIFI_OFF_STATE_BY_EMERGENCY, 1);
	} else {
		/* emergency mode off */
		if (!wifi_off_by_emergency)
			return;

		netconfig_set_vconf_int(VCONF_WIFI_OFF_STATE_BY_EMERGENCY, 0);

		if (wifi_state > VCONFKEY_WIFI_OFF)
			return;

		wifi_power_on();
	}
#endif

}

static void __pm_state_changed_cb(keynode_t* node, void* user_data)
{
	int new_state = -1;
	int wifi_state = 0;
	static int prev_state = VCONFKEY_PM_STATE_NORMAL;

	if (vconf_get_int(VCONFKEY_WIFI_STATE, &wifi_state) < 0) {
		ERR("Fail to get VCONFKEY_WIFI_STATE");
		return;
	}

	/* PM state
	 *	VCONFKEY_PM_STATE_NORMAL = 1,
	 *	VCONFKEY_PM_STATE_LCDDIM,
	 *	VCONFKEY_PM_STATE_LCDOFF,
	 *	VCONFKEY_PM_STATE_SLEEP
	 */
	if (node != NULL)
		new_state = vconf_keynode_get_int(node);
	else
		vconf_get_int(VCONFKEY_PM_STATE, &new_state);

	DBG("wifi state: %d (0 off / 1 on / 2 connected)", wifi_state);
	DBG("Old PM state: %d, current: %d", prev_state, new_state);

	if ((new_state == VCONFKEY_PM_STATE_NORMAL) && (prev_state >= VCONFKEY_PM_STATE_LCDOFF)) {
		netconfig_wifi_bgscan_stop();
		netconfig_wifi_bgscan_start(TRUE);
	}

	prev_state = new_state;
}

#if defined TIZEN_TELEPHONY_ENABLE
static void _tapi_noti_sim_status_cb(TapiHandle *handle, const char *noti_id,
										void *data, void *user_data)
{
	TelSimCardStatus_t *status = data;

	if (*status == TAPI_SIM_STATUS_SIM_INIT_COMPLETED) {
		DBG("Turn Wi-Fi on automatically");
#if defined TIZEN_WEARABLE
		wifi_power_on_wearable(TRUE);
#else
		wifi_power_on();
#endif
		netconfig_tel_deinit();
	}
}

static gboolean netconfig_tapi_check_sim_state(void)
{
	int ret, card_changed;
	TelSimCardStatus_t status = TAPI_SIM_STATUS_UNKNOWN;
	TapiHandle *tapi_handle = NULL;

	tapi_handle = (TapiHandle *)netconfig_tel_init();
	if (tapi_handle == NULL) {
		ERR("Failed to tapi init");
		return FALSE;
	}

	ret = tel_get_sim_init_info(tapi_handle, &status, &card_changed);
	if (ret != TAPI_API_SUCCESS) {
		ERR("tel_get_sim_init_info() Failed : [%d]", ret);
		netconfig_tel_deinit();
		return FALSE;
	}

	switch (status) {
	case TAPI_SIM_STATUS_UNKNOWN:
	case TAPI_SIM_STATUS_CARD_ERROR:
	case TAPI_SIM_STATUS_CARD_NOT_PRESENT:
	case TAPI_SIM_STATUS_CARD_BLOCKED:
	case TAPI_SIM_STATUS_SIM_INIT_COMPLETED:
		break;
	case TAPI_SIM_STATUS_SIM_PIN_REQUIRED:
	case TAPI_SIM_STATUS_SIM_INITIALIZING:
	case TAPI_SIM_STATUS_SIM_PUK_REQUIRED:
	case TAPI_SIM_STATUS_SIM_LOCK_REQUIRED:
	case TAPI_SIM_STATUS_SIM_NCK_REQUIRED:
	case TAPI_SIM_STATUS_SIM_NSCK_REQUIRED:
	case TAPI_SIM_STATUS_SIM_SPCK_REQUIRED:
	case TAPI_SIM_STATUS_SIM_CCK_REQUIRED:
		tel_register_noti_event(tapi_handle, TAPI_NOTI_SIM_STATUS,
				_tapi_noti_sim_status_cb, NULL);
		return FALSE;
	default:
		ERR("not defined status(%d)", status);
		break;
	}

	netconfig_tel_deinit();

	return TRUE;
}

static void __netconfig_telephony_ready_changed_cb(keynode_t * node, void *data)
{
	int telephony_ready = 0;

	if (node != NULL)
		telephony_ready = vconf_keynode_get_bool(node);
	else
		vconf_get_bool(VCONFKEY_TELEPHONY_READY, &telephony_ready);

	if (telephony_ready != 0) {
		if (netconfig_tapi_check_sim_state() == FALSE) {
			DBG("Sim is not initialized yet.");

			goto done;
		}
	} else
		return;

	DBG("Turn Wi-Fi on automatically");

#if defined TIZEN_WEARABLE
	wifi_power_on_wearable(TRUE);
#else
	wifi_power_on();
#endif

done:
	vconf_ignore_key_changed(VCONFKEY_TELEPHONY_READY, __netconfig_telephony_ready_changed_cb);
}
#endif

int wifi_power_driver_and_supplicant(gboolean enable)
{
	/* There are 3 thumb rules for Wi-Fi power management
	 *   1. Do not make exposed API to control wpa_supplicant and driver directly.
	 *      It probably breaks ConnMan technology operation.
	 *
	 *   2. Do not remove driver and wpa_supplicant if ConnMan already enabled.
	 *      It breaks ConnMan technology operation.
	 *
	 *   3. Final the best rule: make it as simple as possible.
	 *      Simple code enables easy maintenance and reduces logical errors.
	 */
	if (enable == TRUE) {
		return _load_driver_and_supplicant();
	} else {
		if (connman_wifi_technology_state == TRUE)
			return -ENOSYS;

		return _remove_driver_and_supplicant();
	}
}

void wifi_power_disable_technology_state_by_only_connman_signal(void)
{
	/* Important: it's only done by ConnMan technology signal update */
	connman_wifi_technology_state = FALSE;
}

void wifi_power_recover_firmware(void)
{
	wifi_firmware_recovery_mode = TRUE;

	netconfig_wifi_bgscan_stop();

	wifi_power_off();
}

int wifi_power_on(void)
{
	int err = 0;
	wifi_tech_state_e tech_state;

	tech_state = wifi_state_get_technology_state();
	if (tech_state >= NETCONFIG_WIFI_TECH_POWERED)
		return -EALREADY;

	if (__is_wifi_restricted() == TRUE)
		return -EPERM;

	if (netconfig_is_wifi_tethering_on() == TRUE) {
		/* TODO: Wi-Fi tethering turns off here */
		/* return TRUE; */
		ERR("Failed to turn tethering off");
		return -EBUSY;
	}

#if defined TIZEN_P2P_ENABLE && !defined WLAN_CONCURRENT_MODE
	if (netconfig_is_wifi_direct_on() == TRUE) {
		if (__netconfig_wifi_direct_power_off() == TRUE)
			return -EINPROGRESS;
		else {
			ERR("Failed to turn Wi-Fi direct off");
			return -EBUSY;
		}
	}
#endif

	err = wifi_power_driver_and_supplicant(TRUE);
	if (err < 0 && err != -EALREADY)
		return err;

	err = _set_connman_technology_power(TRUE);

	return err;
}

int wifi_power_off(void)
{
	int err;

	err = _set_connman_technology_power(FALSE);
	if (err == -EALREADY)
		wifi_state_update_power_state(FALSE);

	return 0;
}

#if defined TIZEN_WEARABLE
int wifi_power_on_wearable(gboolean device_picker_test)
{
	int err = 0;
	int wifi_use = 1;
	wifi_tech_state_e tech_state;
	weconn_service_state_e weconn_state;

	tech_state = wifi_state_get_technology_state();
	if (tech_state >= NETCONFIG_WIFI_TECH_POWERED)
		return -EALREADY;

	err = weconn_get_service_state(weconn_handle, W_SERVICE_TYPE_BT, &weconn_state);
	if (err == 0 && weconn_state == W_SERVICE_STATE_CONNECTED) {
		WARN("Not permitted Wi-Fi on");
		return -EPERM;
	}

	if (vconf_get_int(VCONF_WIFI_WEARABLE_WIFI_USE, &wifi_use) < 0) {
		ERR("Fail to get VCONF_WIFI_WEARABLE_WIFI_USE");
		return -EIO;
	}

	if (wifi_use == 0) {
		WARN("VCONF_WIFI_WEARABLE_WIFI_USE is OFF");
		return -EPERM;
	}

	err = wifi_power_driver_and_supplicant(TRUE);
	if (err < 0 && err != -EALREADY)
		return err;

	err = _set_connman_technology_power(TRUE);

	if (device_picker_test == TRUE)
		netconfig_wifi_enable_device_picker_test();

	return err;
}
#endif

void wifi_power_initialize(void)
{
	int wifi_last_power_state = 0;

	/* Initialize Airplane mode */
#if defined TIZEN_TELEPHONY_ENABLE
	vconf_get_bool(VCONFKEY_TELEPHONY_FLIGHT_MODE, &airplane_mode);
#endif
	DBG("Airplane[%s]", airplane_mode > 0 ? "ON" : "OFF");

	/* Update the last Wi-Fi power state */
	vconf_get_int(VCONF_WIFI_LAST_POWER_STATE, &wifi_last_power_state);
	if (wifi_last_power_state > VCONFKEY_WIFI_OFF) {
#if defined TIZEN_TELEPHONY_ENABLE
		int telephony_ready = 0;
		vconf_get_bool(VCONFKEY_TELEPHONY_READY, &telephony_ready);
		if (telephony_ready == 0) {
			DBG("Telephony API is not initialized yet");
			vconf_notify_key_changed(VCONFKEY_TELEPHONY_READY,
					__netconfig_telephony_ready_changed_cb, NULL);

			goto done;
		} else {
			if (netconfig_tapi_check_sim_state() == FALSE) {
				DBG("SIM is not initialized yet");

				goto done;
			}
		}
#endif
		DBG("Turn Wi-Fi on automatically");
#if defined TIZEN_WEARABLE
		wifi_power_on_wearable(TRUE);
#else
		wifi_power_on();
#endif
	}

#if defined TIZEN_TELEPHONY_ENABLE
done:
#endif

#if defined TIZEN_WEARABLE
	_weconn_set_state_changed_cb(W_SERVICE_TYPE_BT, NULL);
	vconf_notify_key_changed(VCONF_WIFI_WEARABLE_WIFI_USE, __wearable_wifi_use_changed_cb, NULL);

#if defined TIZEN_TELEPHONY_ENABLE
	vconf_notify_key_changed(VCONFKEY_TELEPHONY_FLIGHT_MODE,
			__netconfig_wifi_wearable_airplane_mode, NULL);
#endif
#else
	vconf_notify_key_changed(VCONFKEY_SETAPPL_NETWORK_RESTRICT_MODE,
			__netconfig_wifi_restrict_mode, NULL);
#if defined TIZEN_TELEPHONY_ENABLE
	vconf_notify_key_changed(VCONFKEY_TELEPHONY_FLIGHT_MODE,
			__netconfig_wifi_airplane_mode, NULL);
#endif
#endif

	vconf_notify_key_changed(VCONFKEY_SETAPPL_PSMODE, __emergency_mode_changed_cb, NULL);
	vconf_notify_key_changed(VCONFKEY_PM_STATE, __pm_state_changed_cb, NULL);
}

void wifi_power_deinitialize(void)
{
}

gboolean handle_load_driver(Wifi *wifi,
		GDBusMethodInvocation *context, gboolean device_picker_test)
{
	int err;

	DBG("Wi-Fi power on requested");

	g_return_val_if_fail(wifi != NULL, FALSE);

#if defined TIZEN_WEARABLE
	err = wifi_power_on_wearable(device_picker_test);
#else
	err = wifi_power_on();

	if (device_picker_test == TRUE)
		netconfig_wifi_enable_device_picker_test();
#endif
	if (err < 0) {
		if (err == -EINPROGRESS)
			netconfig_error_inprogress(context);
		else if (err == -EALREADY)
			netconfig_error_already_exists(context);
		else if (err == -EPERM)
			netconfig_error_permission_denied(context);
		else
			netconfig_error_wifi_driver_failed(context);

		return TRUE;
	}


	netconfig_set_vconf_int(VCONF_WIFI_OFF_STATE_BY_AIRPLANE, 0);
	__netconfig_set_wifi_bssid();

	wifi_complete_load_driver(wifi, context);
	return TRUE;
}

gboolean handle_remove_driver(Wifi *wifi, GDBusMethodInvocation *context)
{
	int err;

	DBG("Wi-Fi power off requested");

	g_return_val_if_fail(wifi != NULL, FALSE);

	err = wifi_power_off();
	if (err < 0) {
		if (err == -EINPROGRESS)
			netconfig_error_inprogress(context);
		else if (err == -EALREADY)
			netconfig_error_already_exists(context);
		else if (err == -EPERM)
			netconfig_error_permission_denied(context);
		else
			netconfig_error_wifi_driver_failed(context);
		return TRUE;
	}

	netconfig_set_vconf_int(VCONF_WIFI_OFF_STATE_BY_AIRPLANE, 0);

	wifi_complete_remove_driver(wifi, context);
	return TRUE;
}

gboolean handle_load_p2p_driver(Wifi *wifi, GDBusMethodInvocation *context)
{
	ERR("Deprecated");

	wifi_complete_load_p2p_driver(wifi, context);
	return TRUE;
}

gboolean handle_remove_p2p_driver(Wifi *wifi, GDBusMethodInvocation *context)
{
	ERR("Deprecated");

	wifi_complete_remove_p2p_driver(wifi, context);
	return TRUE;
}

#if defined TIZEN_TV
static int __netconfig_get_random_mac(unsigned char *mac_buf, int mac_len)
{
	DBG("Generate Random Mac address of ethernet");
	FILE *fp;
	int rc;

	fp = fopen(OS_RANDOM_FILE, "rb");

	if (fp == NULL) {
		ERR("Could not open /dev/urandom");
		return -1;
	}
	rc = fread(mac_buf, 1, mac_len, fp);
	if (fp)
		fclose(fp);

	return rc != mac_len ? -1 : 0;
}

void __netconfig_set_ether_macaddr()
{

	DBG("Set wired Mac address ");
	char *mac_addr = NULL;
	int rv = -1;

	mac_addr = vconf_get_str(VCONF_ETH_MAC_ADDRESS);
	if (mac_addr == NULL) {
		DBG("vconf_get_str Failed\n");
		return;
	}
	/* Checking Invalid MAC Address */
	if ((strlen(mac_addr) == 0)) {
		ERR("Failed to get valid MAC Address from vconf");
		/*Generate the Random Mac address*/
		unsigned char rand_mac_add[ETH_MAC_ADDR_SIZE+1];

		if (__netconfig_get_random_mac(rand_mac_add, ETH_MAC_ADDR_SIZE == -1)) {

			ERR("Could not generate the Random Mac address");
			g_free(mac_addr);
			return;
		}

		rand_mac_add[0] &= 0xFE; /*Clear multicase bit*/
		rand_mac_add[0] |= 0x02; /*set local assignment bit*/

		/*Set the Mac address in Vconf*/
		sprintf(mac_addr, "%x:%x:%x:%x:%x:%x",
				rand_mac_add[0], rand_mac_add[1],
				rand_mac_add[2], rand_mac_add[3],
				rand_mac_add[4], rand_mac_add[5]);

		netconfig_set_vconf_str(VCONF_ETH_MAC_ADDRESS, mac_addr);
	}

	DBG("MAC Address of eth0 [%s]",mac_addr);
	const char *path = NET_EXEC_PATH;
	char *const args[] = { "/sbin/ifconfig", "eth0", "hw",
		"ether",mac_addr, "up", NULL};
	char *const envs[] = { NULL };
	rv = netconfig_execute_file(path, args, envs);

	if (rv < 0) {
		ERR("Unable to execute system command");
	}
	g_free(mac_addr);

}
#endif
