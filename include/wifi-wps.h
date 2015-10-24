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

#ifndef __NETCONFIG_WIFI_WPS_H__
#define __NETCONFIG_WIFI_WPS_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "wifi.h"

gboolean netconfig_wifi_is_wps_enabled(void);

void netconfig_wifi_wps_signal_scandone(void);
void netconfig_wifi_wps_signal_scanaborted(void);

gboolean handle_request_wps_scan(Wifi *wifi, GDBusMethodInvocation *context);
gboolean netconfig_iface_wifi_request_wps_cancel(Wifi *wifi, GDBusMethodInvocation **context);

#ifdef __cplusplus
}
#endif

#endif /* __NETCONFIG_WIFI_WPS_H__ */
