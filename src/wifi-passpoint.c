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

#include <errno.h>

#include "log.h"
#include "util.h"
#include "neterror.h"
#include "netdbus.h"
#include "netsupplicant.h"
#include "wifi-passpoint.h"

#if defined TIZEN_WLAN_PASSPOINT
static gboolean netconfig_wifi_get_passpoint(gint32 *enabled)
{
	DBusMessage *reply;
	DBusMessageIter iter, variant;
	dbus_bool_t value;
	gboolean result = FALSE;

	reply = netconfig_supplicant_invoke_dbus_interface_property_get(SUPPLICANT_IFACE_INTERFACE,
				"Passpoint");
	if (reply == NULL) {
		ERR("Error!!! Failed to get passpoint property");
		return result;
	}

	if (dbus_message_get_type(reply) == DBUS_MESSAGE_TYPE_ERROR) {
		const char *err_msg = dbus_message_get_error_name(reply);
		ERR("Error!!! Error message received[%s]", err_msg);
		return result;
	}

	dbus_message_iter_init(reply, &iter);

	if (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_VARIANT) {
		dbus_message_iter_recurse(&iter, &variant);
		if (dbus_message_iter_get_arg_type(&variant) == DBUS_TYPE_INT32) {
			dbus_message_iter_get_basic(&variant, &value);
			if (value == TRUE)
				*enabled = 1;
			else
				*enabled = 0;

			result = TRUE;
		}
	}

	dbus_message_unref(reply);

	return result;
}

static gboolean netconfig_wifi_set_passpoint(gint32 enable)
{
	gint32 value = enable ? 1 : 0;
	gboolean result = FALSE;
	GList *input_args = NULL;

	struct dbus_input_arguments args_enable[2] = {
			{DBUS_TYPE_INT32, &value},
			{DBUS_TYPE_INVALID, NULL}
	};

	input_args = setup_input_args(input_args, args_enable);

	result = netconfig_supplicant_invoke_dbus_interface_property_set(
			SUPPLICANT_IFACE_INTERFACE, "Passpoint",
			DBUS_TYPE_INT32_AS_STRING, input_args, NULL);
	if (result == FALSE)
		ERR("Fail to set passpoint enable[%d]", enable);

	g_list_free(input_args);

	return result;
}
#endif

gboolean netconfig_iface_wifi_get_passpoint(NetconfigWifi *wifi,
		gint32 *result, GError **error)
{
	g_return_val_if_fail(wifi != NULL, FALSE);

#if defined TIZEN_WLAN_PASSPOINT
	if (netconfig_wifi_get_passpoint(result))
		return TRUE;

	return FALSE;
#else
	*result = 0;

	return TRUE;
#endif
}

gboolean netconfig_iface_wifi_set_passpoint(NetconfigWifi *wifi,
		gint32 enable, GError **error)
{
	g_return_val_if_fail(wifi != NULL, FALSE);

#if defined TIZEN_WLAN_PASSPOINT
	return netconfig_wifi_set_passpoint(enable);
#else
	return FALSE;
#endif
}
