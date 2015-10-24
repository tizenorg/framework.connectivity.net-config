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

#include <glib.h>

#include "netdbus.h"
#include "neterror.h"
#include "log.h"

#define NETCONFIG_ERROR_INTERFACE NETCONFIG_SERVICE ".Error"
#define CONNMAN_AGENT_ERROR_INTERFACE "net.connman.Agent.Error"

GQuark netconfig_error_quark(void)
{
	static GQuark quark = 0;

	if (!quark)
		quark = g_quark_from_static_string("netconfig_error");

	return quark;
}

GQuark netconfig_connman_agent_error_quark(void)
{
	static GQuark quark = 0;

	if (!quark)
		quark = g_quark_from_static_string("netconfig_connman_agent_error");

	return quark;
}

void netconfig_error_no_profile(GDBusMethodInvocation *context)
{
	ERR("dbus method return error");
	g_dbus_method_invocation_return_error(context, netconfig_error_quark(),
			NETCONFIG_ERROR_NO_PROFILE,
			NETCONFIG_ERROR_INTERFACE ".NoProfile");
}

void netconfig_error_inprogress(GDBusMethodInvocation *context)
{
	ERR("dbus method return error");
	g_dbus_method_invocation_return_error(context, netconfig_error_quark(),
			NETCONFIG_ERROR_INPROGRESS,
			NETCONFIG_ERROR_INTERFACE ".InProgress");
}

void netconfig_error_already_exists(GDBusMethodInvocation *context)
{
	ERR("dbus method return error");
	g_dbus_method_invocation_return_error(context, netconfig_error_quark(),
			NETCONFIG_ERROR_ALREADYEXISTS,
			NETCONFIG_ERROR_INTERFACE ".AlreadyExists");
}

void netconfig_error_invalid_parameter(GDBusMethodInvocation *context)
{
	ERR("dbus method return error");
	g_dbus_method_invocation_return_error(context, netconfig_error_quark(),
			NETCONFIG_ERROR_INVALID_PARAMETER,
			NETCONFIG_ERROR_INTERFACE ".InvalidParameter");
}

void netconfig_error_permission_denied(GDBusMethodInvocation *context)
{
	ERR("dbus method return error");
	g_dbus_method_invocation_return_error(context, netconfig_error_quark(),
			NETCONFIG_ERROR_PERMISSION_DENIED,
			NETCONFIG_ERROR_INTERFACE ".PermissionDenied");
}

void netconfig_error_wifi_driver_failed(GDBusMethodInvocation *context)
{
	ERR("dbus method return error");
	g_dbus_method_invocation_return_error(context, netconfig_error_quark(),
			NETCONFIG_ERROR_WIFI_DRIVER_FAILURE,
			NETCONFIG_ERROR_INTERFACE ".WifiDriverFailed");
}

void netconfig_error_wifi_direct_failed(GDBusMethodInvocation *context)
{
	ERR("dbus method return error");
	g_dbus_method_invocation_return_error(context, netconfig_error_quark(),
			NETCONFIG_ERROR_WIFI_DRIVER_FAILURE,
			NETCONFIG_ERROR_INTERFACE ".WifiDirectFailed");
}

void netconfig_error_fail_get_imsi(GDBusMethodInvocation *context)
{
	ERR("dbus method return error");
	g_dbus_method_invocation_return_error(context, netconfig_error_quark(),
			NETCONFIG_ERROR_FAILED_GET_IMSI,
			NETCONFIG_ERROR_INTERFACE".FailGetSimImsi");
}

void netconfig_error_fail_req_sim_auth(GDBusMethodInvocation *context)
{
	ERR("dbus method return error");
	g_dbus_method_invocation_return_error(context, netconfig_error_quark(),
			NETCONFIG_ERROR_FAILED_REQ_SIM_AUTH,
			NETCONFIG_ERROR_INTERFACE".FailReqSimAuth");
}

void netconfig_error_fail_req_sim_auth_wrong_param(GDBusMethodInvocation *context)
{
	ERR("dbus method return error");
	g_dbus_method_invocation_return_error(context, netconfig_error_quark(),
			NETCONFIG_ERROR_FAILED_REQ_SIM_AUTH_WRONG_PARAM,
			NETCONFIG_ERROR_INTERFACE".FailReqSimAuthWrongParam");
}

void netconfig_error_fail_get_sim_auth_wrong_data(GDBusMethodInvocation *context)
{
	ERR("dbus method return error");
	g_dbus_method_invocation_return_error(context, netconfig_error_quark(),
			NETCONFIG_ERROR_FAILED_GET_SIM_AUTH_WRONG_DATA,
			NETCONFIG_ERROR_INTERFACE".FailGetSimAuthWrongData");
}

void netconfig_error_fail_get_sim_auth_delay(GDBusMethodInvocation *context)
{
	ERR("dbus method return error");
	g_dbus_method_invocation_return_error(context, netconfig_error_quark(),
			NETCONFIG_ERROR_FAILED_GET_SIM_AUTH_DELAY,
			NETCONFIG_ERROR_INTERFACE".FailGetSimAuthDelay");
}

void netconfig_error_fail_save_congifuration(GDBusMethodInvocation *context)
{
	ERR("dbus method return error");
	g_dbus_method_invocation_return_error(context, netconfig_error_quark(),
			NETCONFIG_ERROR_INTERNAL,
			NETCONFIG_ERROR_INTERFACE".FailSaveConfiguration");
}

#include <glib/gprintf.h>
void netconfig_error_dbus_method_return(GDBusMethodInvocation *context, netconfig_error_e error, const gchar *message)
{
	gchar *msg = NULL;

	ERR("dbus method return error");

	msg = g_strdup_printf("%s.%s", NETCONFIG_ERROR_INTERFACE, message);
	g_dbus_method_invocation_return_error(context, netconfig_error_quark(), error,"%s", msg);

	g_free(msg);
}

void netconfig_error_init(void)
{
	/* TODO: register GError domain to make error_name */
	/*
	dbus_g_error_domain_register(NETCONFIG_ERROR_QUARK,
			NETCONFIG_ERROR_INTERFACE,
			code_num_netconfig);

	dbus_g_error_domain_register(NETCONFIG_CONNMAN_AGENT_ERROR_QUARK,
			CONNMAN_AGENT_ERROR_INTERFACE,
			code_num_connman);
	*/
}
