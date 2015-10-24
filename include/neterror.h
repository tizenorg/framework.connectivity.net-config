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
#include <gio/gio.h>
#include <glib-object.h>

#define NETCONFIG_ERROR_QUARK (netconfig_error_quark())
#define NETCONFIG_CONNMAN_AGENT_ERROR_QUARK (netconfig_connman_agent_error_quark())

typedef enum {
	NETCONFIG_NO_ERROR				= 0x00,
	NETCONFIG_ERROR_INTERNAL 		= 0x01,
	NETCONFIG_ERROR_NO_SERVICE 		= 0x02,
	NETCONFIG_ERROR_TRASPORT 		= 0x03,
	NETCONFIG_ERROR_NO_PROFILE 		= 0x04,
	NETCONFIG_ERROR_WRONG_PROFILE 	= 0x05,
	NETCONFIG_ERROR_INPROGRESS		= 0x06,
	NETCONFIG_ERROR_ALREADYEXISTS	= 0x07,
	NETCONFIG_ERROR_INVALID_PARAMETER		= 0x08,
	NETCONFIG_ERROR_PERMISSION_DENIED		= 0x09,
	NETCONFIG_ERROR_WIFI_DRIVER_FAILURE		= 0x0A,
	NETCONFIG_ERROR_FAILED_GET_IMSI			= 0x0B,
	NETCONFIG_ERROR_FAILED_REQ_SIM_AUTH		= 0x0C,
	NETCONFIG_ERROR_FAILED_REQ_SIM_AUTH_WRONG_PARAM		= 0x0D,
	NETCONFIG_ERROR_FAILED_GET_SIM_AUTH_WRONG_DATA		= 0x0E,
	NETCONFIG_ERROR_FAILED_GET_SIM_AUTH_DELAY			= 0x0F,
	NETCONFIG_ERROR_FAILED_REQ_AKA_AUTH					= 0x10,
	NETCONFIG_ERROR_MAX 								= 0x11,
} netconfig_error_e;

void netconfig_error_no_profile(GDBusMethodInvocation *context);
void netconfig_error_inprogress(GDBusMethodInvocation *context);
void netconfig_error_already_exists(GDBusMethodInvocation *context);
void netconfig_error_invalid_parameter(GDBusMethodInvocation *context);
void netconfig_error_permission_denied(GDBusMethodInvocation *context);
void netconfig_error_wifi_driver_failed(GDBusMethodInvocation *context);
void netconfig_error_wifi_direct_failed(GDBusMethodInvocation *context);
void netconfig_error_fail_get_imsi(GDBusMethodInvocation *context);
void netconfig_error_fail_req_sim_auth(GDBusMethodInvocation *context);
void netconfig_error_fail_req_sim_auth_wrong_param(GDBusMethodInvocation *context);
void netconfig_error_fail_get_sim_auth_wrong_data(GDBusMethodInvocation *context);
void netconfig_error_fail_get_sim_auth_delay(GDBusMethodInvocation *context);
void netconfig_error_fail_save_congifuration(GDBusMethodInvocation *context);
void netconfig_error_dbus_method_return(GDBusMethodInvocation *context, netconfig_error_e error, const gchar *message);

void netconfig_error_init(void);

#ifdef __cplusplus
}
#endif

#endif /* __NETCONFIG_ERROR_H__ */
