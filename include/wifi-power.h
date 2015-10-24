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

#include "wifi.h"

void		wifi_power_initialize(void);
void		wifi_power_deinitialize(void);

int			wifi_power_on(void);
int			wifi_power_off(void);
#if defined TIZEN_WEARABLE
int			wifi_power_on_wearable(gboolean device_picker_test);
#endif

int			wifi_power_driver_and_supplicant(gboolean enable);
void		wifi_power_disable_technology_state_by_only_connman_signal(void);
void		wifi_power_recover_firmware(void);

gboolean	handle_load_driver(Wifi *wifi, GDBusMethodInvocation *context, gboolean device_picker_test);
gboolean	handle_remove_driver(Wifi *wifi, GDBusMethodInvocation *context);
gboolean	handle_load_p2p_driver(Wifi *wifi, GDBusMethodInvocation *context);
gboolean	handle_remove_p2p_driver(Wifi *wifi, GDBusMethodInvocation *context);

#if defined TIZEN_TV
       void __netconfig_set_ether_macaddr();
#endif

#ifdef __cplusplus
}
#endif

#endif /* __NETCONFIG_WIFI_POWER_H__ */
