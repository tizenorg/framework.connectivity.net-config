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

#ifndef __NETCONFIG_NETWORK_STATE_H__
#define __NETCONFIG_NETWORK_STATE_H__

#ifdef __cplusplus
extern "C" {
#endif

void netconfig_network_notify_ethernet_cable_state(const char *key);

const char		*netconfig_get_default_profile(void);
const char		*netconfig_get_default_ifname(void);
const char		*netconfig_get_default_ipaddress(void);
const char		*netconfig_get_default_ipaddress6(void);
const char		*netconfig_get_default_proxy(void);
unsigned int	netconfig_get_default_frequency(void);
const char		*netconfig_wifi_get_connected_essid(const char *default_profile);

void			netconfig_update_default(void);
void			netconfig_update_default_profile(const char *profile);
char			*netconfig_get_ifname(const char *profile);

void state_object_create_and_init(void);
void state_object_deinit(void);

#ifdef __cplusplus
}
#endif

#endif /* __NETCONFIG_NETWORK_STATE_H__ */
