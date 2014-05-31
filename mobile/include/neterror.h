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

#ifndef __NETCONFIG_ERROR_H__
#define __NETCONFIG_ERROR_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "glib.h"

G_BEGIN_DECLS

typedef enum {
	NETCONFIG_NO_ERROR				= 0x00,
	NETCONFIG_ERROR_INTERNAL 		= 0x01,
	NETCONFIG_ERROR_NO_SERVICE 		= 0x02,
	NETCONFIG_ERROR_TRASPORT 		= 0x03,
	NETCONFIG_ERROR_NO_PROFILE 		= 0x04,
	NETCONFIG_ERROR_WRONG_PROFILE 	= 0x05,
	NETCONFIG_ERROR_WIFI_LOAD_INPROGRESS = 0x06,
	NETCONFIG_ERROR_WIFI_DRIVER_FAILURE = 0x07,
	NETCONFIG_ERROR_SECURITY_RESTRICTED = 0x08,
	NETCONFIG_ERROR_FAILED_GET_IMSI = 0x09,
	NETCONFIG_ERROR_FAILED_REQ_SIM_AUTH = 0x0A,
	NETCONFIG_ERROR_FAILED_REQ_SIM_AUTH_WRONG_PARAM = 0x0B,
	NETCONFIG_ERROR_FAILED_GET_SIM_AUTH_WRONG_DATA = 0x0C,
	NETCONFIG_ERROR_FAILED_GET_SIM_AUTH_DELAY = 0x0D,
	NETCONFIG_ERROR_MAX 			= 0x0E,
} NETCONFIG_ERROR;

GQuark netconfig_error_quark(void);

#define	NETCONFIG_ERROR_QUARK	(netconfig_error_quark())

G_END_DECLS

#ifdef __cplusplus
}
#endif

void netconfig_error_wifi_load_inprogress(GError **error);
void netconfig_error_wifi_driver_failed(GError **error);
void netconfig_error_security_restricted(GError **error);
void netconfig_error_wifi_direct_failed(GError **error);
void netconfig_error_fail_get_imsi(GError **error);
void netconfig_error_fail_req_sim_auth(GError **error);
void netconfig_error_fail_req_sim_auth_wrong_param(GError **error);
void netconfig_error_fail_get_sim_auth_wrong_data(GError **error);
void netconfig_error_fail_get_sim_auth_delay(GError **error);

#endif /* __NETCONFIG_ERROR_H__ */
