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

#ifndef __NETCONFIG_WIFI_INDICATOR_H__
#define __NETCONFIG_WIFI_INDICATOR_H__

#ifdef __cplusplus
extern "C" {
#endif

int netconfig_wifi_get_rssi(void);

void netconfig_wifi_indicator_start(void);
void netconfig_wifi_indicator_stop(void);

#ifdef __cplusplus
}
#endif

#endif /* __NETCONFIG_WIFI_INDICATOR_H__ */
