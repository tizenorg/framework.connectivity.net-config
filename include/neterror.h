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

#ifndef __NETCONFIG_ERROR_H__
#define __NETCONFIG_ERROR_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "glib.h"

#define NETCONFIG_ERROR_QUARK (netconfig_error_quark())
#define NETCONFIG_CONNMAN_AGENT_ERROR_QUARK (netconfig_connman_agent_error_quark())

void netconfig_error_inprogress(GError **error);
void netconfig_error_already_exists(GError **error);
void netconfig_error_invalid_parameter(GError **error);
void netconfig_error_permission_denied(GError **error);
void netconfig_error_wifi_driver_failed(GError **error);
void netconfig_error_wifi_direct_failed(GError **error);
void netconfig_error_fail_get_imsi(GError **error);
void netconfig_error_fail_req_sim_auth(GError **error);
void netconfig_error_fail_req_sim_auth_wrong_param(GError **error);
void netconfig_error_fail_get_sim_auth_wrong_data(GError **error);
void netconfig_error_fail_get_sim_auth_delay(GError **error);

void netconfig_error_init(void);

#ifdef __cplusplus
}
#endif

#endif /* __NETCONFIG_ERROR_H__ */
