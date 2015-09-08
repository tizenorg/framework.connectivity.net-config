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

#ifndef __NETCONFIG_WIFI_POWER_H__
#define __NETCONFIG_WIFI_POWER_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <glib.h>

void netconfig_wifi_power_initialize(void);

int netconfig_wifi_on(void);
int netconfig_wifi_off(void);
void netconfig_wifi_fetch_airplane_mode(void);
int netconfig_wifi_driver_and_supplicant(gboolean enable);

void netconfig_wifi_disable_technology_state_by_only_connman_signal(void);

void netconfig_wifi_recover_firmware(void);

gboolean netconfig_iface_wifi_load_driver(
		NetconfigWifi *wifi, gboolean device_picker_test, GError **error);
gboolean netconfig_iface_wifi_remove_driver(
		NetconfigWifi *wifi, GError **error);

gboolean netconfig_iface_wifi_load_p2p_driver(
		NetconfigWifi *wifi, GError **error);
gboolean netconfig_iface_wifi_remove_p2p_driver(
		NetconfigWifi *wifi, GError **error);

#ifdef __cplusplus
}
#endif

#endif /* __NETCONFIG_WIFI_POWER_H__ */
