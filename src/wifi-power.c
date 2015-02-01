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

#if defined TIZEN_P2P_ENABLE && !defined WLAN_CONCURRENT_MODE
#if defined TIZEN_P2P_ENABLE
#include <wifi-direct.h>
#endif
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

#include "mdm-private.h"

#define WLAN_SUPPLICANT_SCRIPT		"/usr/sbin/wpa_supp.sh"
#define P2P_SUPPLICANT_SCRIPT		"/usr/sbin/p2p_supp.sh"
#define VCONF_WIFI_OFF_STATE_BY_AIRPLANE \
			"file/private/wifi/wifi_off_by_airplane"
#define VCONF_WIFI_OFF_STATE_BY_RESTRICTED \
			"file/private/wifi/wifi_off_by_restricted"
#define VCONF_WIFI_OFF_STATE_BY_EMERGENCY \
			"file/private/wifi/wifi_off_by_emergency"

#if defined TIZEN_WEARABLE
#define VCONF_WIFI_WEARABLE_WIFI_USE \
			"db/private/wifi/wearable_wifi_use"
#endif

static gboolean connman_wifi_technology_state = FALSE;

static gboolean wifi_firmware_recovery_mode = FALSE;

static int airplane_mode = 0;

static void __netconfig_wifi_technology_reply(DBusPendingCall *call, void *data)
{
	DBusMessage *message;

	message = dbus_pending_call_steal_reply(call);

	if (dbus_message_get_type(message) == DBUS_MESSAGE_TYPE_ERROR) {
		ERR("%s", dbus_message_get_error_name(message));

		if (dbus_message_is_error(message,
				CONNMAN_ERROR_INTERFACE ".AlreadyEnabled") == TRUE)
			netconfig_wifi_update_power_state(TRUE);
		else if (dbus_message_is_error(message,
				CONNMAN_ERROR_INTERFACE ".AlreadyDisabled") == TRUE)
			netconfig_wifi_update_power_state(FALSE);
	} else {
		DBG("Successfully requested");
	}

	dbus_message_unref(message);
	dbus_pending_call_unref(call);
}

static gboolean __netconfig_is_wifi_restricted(void)
{
	int restricted_mode = 0;

	vconf_get_bool(VCONFKEY_SETAPPL_NETWORK_RESTRICT_MODE, &restricted_mode);
	if (restricted_mode != 0) {
		DBG("network restricted mode[%d]", restricted_mode);
		return TRUE;
	}

	return FALSE;
}

static int __netconfig_wifi_connman_technology(gboolean enable)
{
	gboolean reply = FALSE;
	char key[] = "string:Powered";
	char value_enable[] = "variant:boolean:true";
	char value_disable[] = "variant:boolean:false";
	char *param_array[] = { NULL, NULL, NULL };

	if (connman_wifi_technology_state == enable)
		return -EALREADY;

	param_array[0] = key;
	if (enable == TRUE)
		param_array[1] = value_enable;
	else
		param_array[1] = value_disable;

	reply = netconfig_invoke_dbus_method_nonblock(CONNMAN_SERVICE,
			CONNMAN_WIFI_TECHNOLOGY_PREFIX, CONNMAN_TECHNOLOGY_INTERFACE,
			"SetProperty", param_array, __netconfig_wifi_technology_reply);

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
		netconfig_wifi_state_set_technology_state(NETCONFIG_WIFI_TECH_WPS_ONLY);

	return 0;
}

static int __netconfig_wifi_supplicant(gboolean enable)
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

void netconfig_wifi_recover_firmware(void)
{
	wifi_firmware_recovery_mode = TRUE;

	netconfig_wifi_bgscan_stop();

	netconfig_wifi_off();
}

#if defined TIZEN_P2P_ENABLE && !defined WLAN_CONCURRENT_MODE
static void __netconfig_wifi_direct_state_cb(int error_code,
		wifi_direct_device_state_e device_state, void *user_data)
{
	int err;

	wifi_direct_unset_device_state_changed_cb();
	wifi_direct_deinitialize();

	if (device_state == WIFI_DIRECT_DEVICE_STATE_DEACTIVATED) {
		err = netconfig_wifi_on();
		if (err < 0) {
			if (err == -EALREADY)
				netconfig_wifi_update_power_state(TRUE);
			else
				netconfig_wifi_notify_power_failed();
		}
	}
}

static gboolean __netconfig_wifi_direct_power_off(void)
{
	DBG("Wi-Fi direct is turning off");

	if (wifi_direct_initialize() < 0)
		return FALSE;

	if (wifi_direct_set_device_state_changed_cb(
			__netconfig_wifi_direct_state_cb, NULL) < 0)
		return FALSE;

	if (wifi_direct_deactivate() < 0)
		return FALSE;

	return TRUE;
}
#endif

static int __netconfig_wifi_try_to_load_driver_and_supplicant(void)
{
	int err = 0;
	enum netconfig_wifi_tech_state wifi_tech_state;

	wifi_tech_state = netconfig_wifi_state_get_technology_state();
	if (wifi_tech_state > NETCONFIG_WIFI_TECH_OFF)
		return -EALREADY;

	err = __netconfig_wifi_supplicant(TRUE);
	if (err < 0 && err != -EALREADY)
		return err;

	err = netconfig_wifi_firmware(NETCONFIG_WIFI_STA, TRUE);
	if (err < 0 && err != -EALREADY) {
		__netconfig_wifi_supplicant(FALSE);
		return err;
	}

	netconfig_wifi_state_set_technology_state(NETCONFIG_WIFI_TECH_WPS_ONLY);

	return 0;
}

static int __netconfig_wifi_try_to_remove_driver_and_supplicant(void)
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

	err = __netconfig_wifi_supplicant(FALSE);
	if (err < 0 && err != -EALREADY)
		return err;

	netconfig_wifi_state_set_technology_state(NETCONFIG_WIFI_TECH_OFF);

	if (wifi_firmware_recovery_mode == TRUE) {
		if (netconfig_wifi_on() < 0)
			ERR("Failed to recover Wi-Fi firmware");

		wifi_firmware_recovery_mode = FALSE;
	}

	return 0;
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
		return __netconfig_wifi_try_to_load_driver_and_supplicant();
	else {
		if (connman_wifi_technology_state == TRUE)
			return -ENOSYS;

		return __netconfig_wifi_try_to_remove_driver_and_supplicant();
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
	enum netconfig_wifi_tech_state wifi_tech_state;

	wifi_tech_state = netconfig_wifi_state_get_technology_state();
	if (wifi_tech_state >= NETCONFIG_WIFI_TECH_POWERED)
		return -EALREADY;

	if (netconfig_is_wifi_allowed() != TRUE) {
		ERR("MDM: Wi-Fi disabled");
		netconfig_send_message_to_net_popup("Network connection popup",
						"wifi restricted", "popup", NULL);
		return -EPERM;
	}

	if (__netconfig_is_wifi_restricted() == TRUE)
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

	err = netconfig_wifi_driver_and_supplicant(TRUE);
	if (err < 0 && err != -EALREADY)
		return err;

	err = __netconfig_wifi_connman_technology(TRUE);

	return err;
}

int netconfig_wifi_off(void)
{
	int err;

	__netconfig_p2p_supplicant(FALSE);

	err = __netconfig_wifi_connman_technology(FALSE);
	if (err == -EALREADY)
		netconfig_wifi_update_power_state(FALSE);

	return 0;
}

#if defined TIZEN_WEARABLE
int netconfig_wifi_on_wearable(void)
{
	int err = 0;
	int wifi_use;
	int ps_mode;
	enum netconfig_wifi_tech_state wifi_tech_state;

	wifi_tech_state = netconfig_wifi_state_get_technology_state();
	if (wifi_tech_state >= NETCONFIG_WIFI_TECH_POWERED)
		return -EALREADY;

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

	err = netconfig_wifi_driver_and_supplicant(TRUE);
	if (err < 0 && err != -EALREADY)
		return err;

	err = __netconfig_wifi_connman_technology(TRUE);

	return err;
}

static void __netconfig_wifi_wearable_wifi_use_mode(keynode_t* node,
		void* user_data)
{
	int wifi_state;
	int wifi_use;

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

		netconfig_wifi_on_wearable();
	} else {
		DBG("wifi use off");
		if (wifi_state == VCONFKEY_WIFI_OFF) {
			WARN("Wi-Fi is already turned off");
			return;
		}

		netconfig_wifi_off();
	}
}
#endif

void netconfig_wifi_fetch_airplane_mode(void)
{
	int airplane_state = 0;
	vconf_get_bool(VCONFKEY_TELEPHONY_FLIGHT_MODE, &airplane_state);
	airplane_mode = airplane_state;
	DBG("airplane mode %s", airplane_state > 0 ? "ON" : "OFF");
}

#if defined TIZEN_WEARABLE
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
#else
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

		netconfig_wifi_off();

		netconfig_set_vconf_int(VCONF_WIFI_OFF_STATE_BY_AIRPLANE, 1);
	} else {
		/* airplane mode off */
		if (!wifi_off_by_airplane)
			return;

		netconfig_set_vconf_int(VCONF_WIFI_OFF_STATE_BY_AIRPLANE, 0);

		if (wifi_state > VCONFKEY_WIFI_OFF)
			return;

		netconfig_wifi_on();
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

		netconfig_wifi_off();

		netconfig_set_vconf_int(VCONF_WIFI_OFF_STATE_BY_RESTRICTED, 1);
	} else {
		/* network restricted off */
		if (!wifi_off_by_restricted)
			return;

		netconfig_set_vconf_int(VCONF_WIFI_OFF_STATE_BY_RESTRICTED, 0);

		if (wifi_state > VCONFKEY_WIFI_OFF)
			return;

		netconfig_wifi_on();
	}
}

static void __netconfig_wifi_emergency_mode(keynode_t *node, void *user_data)
{
	int wifi_state = 0, emergency = 0;
	int wifi_off_by_emergency = 0;
#if !defined TIZEN_WEARABLE
	int emergency_by_fmm = 0;
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
	DBG("Wi-Fi state %d, Wi-Fi was off by emergency mode %s", wifi_state,
			wifi_off_by_emergency ? "Yes" : "No");

#if defined TIZEN_WEARABLE
	if (emergency == SETTING_PSMODE_WEARABLE) {
		/* basic power saving mode on */
	} else if (emergency == SETTING_PSMODE_WEARABLE_ENHANCED) {
		/* enhanced power saving mode on */
		if (wifi_state == VCONFKEY_WIFI_OFF)
			return;

		netconfig_wifi_off();

		netconfig_set_vconf_int(VCONF_WIFI_OFF_STATE_BY_EMERGENCY, 1);
	} else {
		/* power saving mode off */
		if (!wifi_off_by_emergency)
			return;

		netconfig_set_vconf_int(VCONF_WIFI_OFF_STATE_BY_EMERGENCY, 0);

		if (wifi_state > VCONFKEY_WIFI_OFF)
			return;

		netconfig_wifi_on_wearable();
	}
#else
	if (emergency > SETTING_PSMODE_POWERFUL) {
		/* emergency mode on */
		if (wifi_state == VCONFKEY_WIFI_OFF)
			return;

		netconfig_wifi_off();

		netconfig_set_vconf_int(VCONF_WIFI_OFF_STATE_BY_EMERGENCY, 1);
	} else {
		/* emergency mode off */
		if (!wifi_off_by_emergency)
			return;

		netconfig_set_vconf_int(VCONF_WIFI_OFF_STATE_BY_EMERGENCY, 0);

		if (wifi_state > VCONFKEY_WIFI_OFF)
			return;

		netconfig_wifi_on();
	}
#endif

}

static void __netconfig_wifi_pm_state_mode(keynode_t* node, void* user_data)
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

	if ((new_state == VCONFKEY_PM_STATE_NORMAL) &&
			(prev_state >= VCONFKEY_PM_STATE_LCDOFF)) {

		netconfig_wifi_bgscan_stop();
		netconfig_wifi_bgscan_start(TRUE);
	} else if ((new_state == VCONFKEY_PM_STATE_LCDOFF) &&
			(prev_state < VCONFKEY_PM_STATE_LCDOFF)) {
	}

	prev_state = new_state;
}

static void _tapi_noti_sim_status_cb(TapiHandle *handle, const char *noti_id,
										void *data, void *user_data)
{
	TelSimCardStatus_t *status = data;

	if (*status == TAPI_SIM_STATUS_SIM_INIT_COMPLETED) {
		DBG("Turn Wi-Fi on automatically");
#if defined TIZEN_WEARABLE
		netconfig_wifi_on_wearable();
#else
		netconfig_wifi_on();
#endif
		netconfig_tel_deinit();
	}
}

static gboolean netconfig_tapi_check_sim_state(void)
{
	int ret, card_changed;
	TelSimCardStatus_t status;
	TapiHandle *tapi_handle = NULL;

	tapi_handle = (TapiHandle *)netconfig_tel_init();

	ret = tel_get_sim_init_info(tapi_handle, &status, &card_changed);
	if (ret != TAPI_API_SUCCESS) {
		ERR("tel_get_sim_init_info() Failed");
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

static void __netconfig_tapi_state_changed_cb(keynode_t * node, void *data)
{
	int tapi_state = 0;

	if (node != NULL)
		tapi_state = vconf_keynode_get_int(node);
	else
		vconf_get_int(VCONFKEY_TELEPHONY_TAPI_STATE, &tapi_state);

	if (tapi_state != VCONFKEY_TELEPHONY_TAPI_STATE_NONE) {
		if (netconfig_tapi_check_sim_state() == FALSE) {
			DBG("Sim is not initialized yet.");

			goto done;
		}
	} else
		return;

	DBG("Turn Wi-Fi on automatically");

#if defined TIZEN_WEARABLE
	netconfig_wifi_on_wearable();
#else
	netconfig_wifi_on();
#endif

done:
	vconf_ignore_key_changed(VCONFKEY_TELEPHONY_TAPI_STATE,
			__netconfig_tapi_state_changed_cb);
}

void netconfig_wifi_power_initialize(void)
{
	int tapi_state = 0;
	int airplane_state = 0;
	int wifi_last_power_state = 0;

	vconf_get_int(VCONF_WIFI_LAST_POWER_STATE, &wifi_last_power_state);

	if (wifi_last_power_state > VCONFKEY_WIFI_OFF) {
		vconf_get_bool(VCONFKEY_TELEPHONY_FLIGHT_MODE, &airplane_state);

		if (airplane_state == 0) {
			vconf_get_int(VCONFKEY_TELEPHONY_TAPI_STATE, &tapi_state);

			if (tapi_state == VCONFKEY_TELEPHONY_TAPI_STATE_NONE) {
				vconf_notify_key_changed(VCONFKEY_TELEPHONY_TAPI_STATE,
						__netconfig_tapi_state_changed_cb, NULL);

				goto done;
			} else {
				if (netconfig_tapi_check_sim_state() == FALSE) {
					DBG("Sim is not initialized yet.");

					goto done;
				}
			}
		}

		DBG("Turn Wi-Fi on automatically");

#if defined TIZEN_WEARABLE
		netconfig_wifi_on_wearable();
#else
		netconfig_wifi_on();
#endif
	}

done:
#if defined TIZEN_WEARABLE
	vconf_notify_key_changed(VCONF_WIFI_WEARABLE_WIFI_USE,
			__netconfig_wifi_wearable_wifi_use_mode, NULL);
#endif

#if defined TIZEN_WEARABLE
	vconf_notify_key_changed(VCONFKEY_TELEPHONY_FLIGHT_MODE,
			__netconfig_wifi_wearable_airplane_mode, NULL);
#else
	vconf_notify_key_changed(VCONFKEY_TELEPHONY_FLIGHT_MODE,
			__netconfig_wifi_airplane_mode, NULL);
#endif

	vconf_notify_key_changed(VCONFKEY_SETAPPL_NETWORK_RESTRICT_MODE,
			__netconfig_wifi_restrict_mode, NULL);

	vconf_notify_key_changed(VCONFKEY_SETAPPL_PSMODE,
			__netconfig_wifi_emergency_mode, NULL);

	vconf_notify_key_changed(VCONFKEY_PM_STATE,
			__netconfig_wifi_pm_state_mode, NULL);
}

gboolean netconfig_iface_wifi_load_driver(NetconfigWifi *wifi,
		gboolean device_picker_test, GError **error)
{
	int err;

	DBG("Wi-Fi power on requested");

	g_return_val_if_fail(wifi != NULL, FALSE);

#if defined TIZEN_WEARABLE
	err = netconfig_wifi_on_wearable();
#else
	err = netconfig_wifi_on();
#endif
	if (err < 0) {
		if (err == -EINPROGRESS)
			netconfig_error_inprogress(error);
		else if (err == -EALREADY)
			netconfig_error_already_exists(error);
		else if (err == -EPERM)
			netconfig_error_permission_denied(error);
		else
			netconfig_error_wifi_driver_failed(error);

		return FALSE;
	}

	if (device_picker_test == TRUE)
		netconfig_wifi_enable_device_picker_test();

	netconfig_set_vconf_int(VCONF_WIFI_OFF_STATE_BY_AIRPLANE, 0);

	return TRUE;
}

gboolean netconfig_iface_wifi_remove_driver(NetconfigWifi *wifi, GError **error)
{
	int err;

	DBG("Wi-Fi power off requested");

	g_return_val_if_fail(wifi != NULL, FALSE);

	err = netconfig_wifi_off();
	if (err < 0) {
		if (err == -EINPROGRESS)
			netconfig_error_inprogress(error);
		else if (err == -EALREADY)
			netconfig_error_already_exists(error);
		else if (err == -EPERM)
			netconfig_error_permission_denied(error);
		else
			netconfig_error_wifi_driver_failed(error);

		return FALSE;
	}

	netconfig_set_vconf_int(VCONF_WIFI_OFF_STATE_BY_AIRPLANE, 0);

	return TRUE;
}

gboolean netconfig_iface_wifi_load_p2p_driver(NetconfigWifi *wifi, GError **error)
{
	int err = 0;

	DBG("P2P power on requested");

	g_return_val_if_fail(wifi != NULL, FALSE);

#if defined TIZEN_WEARABLE
	err = netconfig_wifi_on_wearable();
#elif defined WLAN_CONCURRENT_MODE
	err = netconfig_wifi_on();
#else
	err = netconfig_wifi_firmware(NETCONFIG_WIFI_STA, TRUE);
#endif
	if (err < 0)
		if (err != -EINPROGRESS && err != -EALREADY)
			return FALSE;

	netconfig_set_vconf_int(VCONF_WIFI_OFF_STATE_BY_AIRPLANE, 0);

	err = __netconfig_p2p_supplicant(TRUE);
	if (err < 0)
		return FALSE;

	return TRUE;
}

gboolean netconfig_iface_wifi_remove_p2p_driver(NetconfigWifi *wifi, GError **error)
{
	int err = 0;

	DBG("P2P power off requested");

	g_return_val_if_fail(wifi != NULL, FALSE);

	err = __netconfig_p2p_supplicant(FALSE);
	if (err < 0)
		return FALSE;

	return TRUE;
}

