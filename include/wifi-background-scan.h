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

#ifndef __NETCONFIG_WIFIBACKGROUND_SCAN_H__
#define __NETCONFIG_WIFIBACKGROUND_SCAN_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "wifi.h"

void netconfig_wifi_bgscan_start(gboolean immediate_scan);
void netconfig_wifi_bgscan_stop(void);
gboolean netconfig_wifi_get_bgscan_state(void);

gboolean netconfig_wifi_get_scanning(void);
void netconfig_wifi_set_scanning(gboolean scanning);
gboolean netconfig_wifi_is_bgscan_paused(void);
void netconfig_wifi_set_bgscan_pause(gboolean pause);

gboolean handle_set_bgscan(Wifi *wifi, GDBusMethodInvocation *context, guint scan_mode);
gboolean handle_resume_bgscan(Wifi *wifi, GDBusMethodInvocation *context);
gboolean handle_pause_bgscan(Wifi *wifi, GDBusMethodInvocation *context);


#ifdef __cplusplus
}
#endif

#endif /* __NETCONFIG_WIFIBACKGROUND_SCAN_H__ */
