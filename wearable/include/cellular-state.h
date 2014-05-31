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

#ifndef __NETCONFIG_CELLULAR_STATE_H__
#define __NETCONFIG_CELLULAR_STATE_H__

#ifdef __cplusplus
extern "C" {
#endif

enum netconfig_cellular_service_state {
	NETCONFIG_CELLULAR_UNKNOWN	= 0x00,
	NETCONFIG_CELLULAR_IDLE		= 0x01,
	NETCONFIG_CELLULAR_ONLINE	= 0x02,
};

struct netconfig_cellular_state_notifier {
	void (*netconfig_cellular_state_changed)
		(enum netconfig_cellular_service_state, void *user_data);
	void *user_data;
};

void netconfig_cellular_state_set_service_state(
		enum netconfig_cellular_service_state new_state);
enum netconfig_cellular_service_state
		netconfig_cellular_state_get_service_state(void);

void netconfig_cellular_state_notifier_cleanup(void);
void netconfig_cellular_state_notifier_register(
		struct netconfig_cellular_state_notifier *notifier);
void netconfig_cellular_state_notifier_unregister(
		struct netconfig_cellular_state_notifier *notifier);

#ifdef __cplusplus
}
#endif

#endif /* __NETCONFIG_CELLULAR_STATE_H__ */
