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

#ifndef __NETCONFIG_WIFI_STATE_H__
#define __NETCONFIG_WIFI_STATE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <glib.h>

typedef enum {
	NETCONFIG_WIFI_UNKNOWN		= 0x00,
	NETCONFIG_WIFI_IDLE			= 0x01,
	NETCONFIG_WIFI_ASSOCIATION	= 0x02,
	NETCONFIG_WIFI_CONFIGURATION	= 0x03,
	NETCONFIG_WIFI_CONNECTED	= 0x04,
	NETCONFIG_WIFI_FAILURE		= 0x05,
} wifi_service_state_e;

typedef enum {
	NETCONFIG_WIFI_TECH_UNKNOWN		= 0x00,
	NETCONFIG_WIFI_TECH_OFF				= 0x01,
	NETCONFIG_WIFI_TECH_WPS_ONLY		= 0x02,
	NETCONFIG_WIFI_TECH_POWERED			= 0x03,
	NETCONFIG_WIFI_TECH_CONNECTED		= 0x04,
	NETCONFIG_WIFI_TECH_TETHERED		= 0x05,
} wifi_tech_state_e;

typedef struct {
	void (*wifi_state_changed)(wifi_service_state_e, void *user_data);
	void *user_data;
} wifi_state_notifier;

#define VCONF_WIFI_LAST_POWER_STATE "file/private/wifi/last_power_state"

void					wifi_state_update_power_state(gboolean powered);
void					wifi_state_emit_power_completed(gboolean power_on);
void					wifi_state_emit_power_failed(void);

char 					*wifi_get_favorite_service(void);
void					wifi_start_timer_network_notification(void);

void					wifi_state_notifier_register(wifi_state_notifier *notifier);
void					wifi_state_notifier_unregister(wifi_state_notifier *notifier);
void					wifi_state_notifier_cleanup(void);

void					wifi_state_set_bss_found(gboolean found);
gboolean				wifi_state_is_bss_found(void);

void					wifi_state_set_service_state(wifi_service_state_e new_state);
wifi_service_state_e	wifi_state_get_service_state(void);

void					wifi_state_set_tech_state(wifi_tech_state_e new_state);
wifi_tech_state_e		wifi_state_get_technology_state(void);

void					wifi_state_set_connected_essid(void);
void					wifi_state_get_connected_essid(gchar **essid);

gboolean				handle_get_wifi_state(Wifi *wifi, GDBusMethodInvocation *context);


#ifdef __cplusplus
}
#endif

#endif /* __NETCONFIG_WIFI_STATE_H__ */
