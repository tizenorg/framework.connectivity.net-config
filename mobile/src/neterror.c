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

#include <glib.h>

#include "neterror.h"
#include "netconfig.h"

#define NETCONFIG_ERROR_INTERFACE NETCONFIG_SERVICE ".Error"

GQuark netconfig_error_quark(void)
{
	static GQuark quark = 0;

	if (!quark)
		quark = g_quark_from_static_string("netconfig_error");

	return quark;
}

void netconfig_error_wifi_load_inprogress(GError **error)
{
	g_set_error(error, netconfig_error_quark(), NETCONFIG_ERROR_WIFI_LOAD_INPROGRESS,
			NETCONFIG_ERROR_INTERFACE ".WifiLoadInprogress");
}

void netconfig_error_wifi_driver_failed(GError **error)
{
	g_set_error(error, netconfig_error_quark(), NETCONFIG_ERROR_WIFI_DRIVER_FAILURE,
			NETCONFIG_ERROR_INTERFACE ".WifiDriverFailed");
}

void netconfig_error_security_restricted(GError **error)
{
	g_set_error(error, netconfig_error_quark(), NETCONFIG_ERROR_SECURITY_RESTRICTED,
			NETCONFIG_ERROR_INTERFACE ".SecurityRestricted");
}

void netconfig_error_wifi_direct_failed(GError **error)
{
	g_set_error(error, netconfig_error_quark(), NETCONFIG_ERROR_WIFI_DRIVER_FAILURE,
			NETCONFIG_ERROR_INTERFACE ".WifiDirectFailed");
}

void netconfig_error_fail_get_imsi(GError **error)
{
	g_set_error(error, netconfig_error_quark(), NETCONFIG_ERROR_FAILED_GET_IMSI,
			NETCONFIG_ERROR_INTERFACE".FailGetSimImsi");
}

void netconfig_error_fail_req_sim_auth(GError **error)
{
	g_set_error(error, netconfig_error_quark(), NETCONFIG_ERROR_FAILED_REQ_SIM_AUTH,
			NETCONFIG_ERROR_INTERFACE".FailReqSimAuth");
}

void netconfig_error_fail_req_sim_auth_wrong_param(GError **error)
{
	g_set_error(error, netconfig_error_quark(), NETCONFIG_ERROR_FAILED_REQ_SIM_AUTH_WRONG_PARAM,
			NETCONFIG_ERROR_INTERFACE".FailReqSimAuthWrongParam");
}

void netconfig_error_fail_get_sim_auth_wrong_data(GError **error)
{
	g_set_error(error, netconfig_error_quark(), NETCONFIG_ERROR_FAILED_GET_SIM_AUTH_WRONG_DATA,
			NETCONFIG_ERROR_INTERFACE".FailGetSimAuthWrongData");
}

void netconfig_error_fail_get_sim_auth_delay(GError **error)
{
	g_set_error(error, netconfig_error_quark(), NETCONFIG_ERROR_FAILED_GET_SIM_AUTH_DELAY,
			NETCONFIG_ERROR_INTERFACE".FailGetSimAuthDelay");
}
