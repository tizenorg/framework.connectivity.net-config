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

#ifndef __NETCONFIG_WIFI_AGENT_H__
#define __NETCONFIG_WIFI_AGENT_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "wifi.h"

gboolean connman_register_agent(void);
gboolean connman_unregister_agent(void);

gboolean netconfig_wifi_set_agent_field_for_eap_network(
		const char *name, const char *identity, const char *passphrase);

gboolean handle_set_field(NetConnmanAgent *connman_agent,
		GDBusMethodInvocation *context, const gchar *service, GVariant *fields);
gboolean handle_request_input(NetConnmanAgent *connman_agent,
		GDBusMethodInvocation *context, const gchar *service, GVariant *fields);
gboolean handle_report_error(NetConnmanAgent *connman_agent,
		GDBusMethodInvocation *context,
		const gchar *service, const gchar *error);

gboolean handle_request_browser(NetConnmanAgent *connman_agent,
		GDBusMethodInvocation *context,
		const gchar *service, const gchar *url);

#ifdef __cplusplus
}
#endif

#endif /* __NETCONFIG_WIFI_AGENT_H__ */
