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
	GVariant *reply;
	gboolean value;
	gboolean result = FALSE;

	reply = netconfig_supplicant_invoke_dbus_interface_property_get(SUPPLICANT_IFACE_INTERFACE,
				"Passpoint");
	if (reply == NULL) {
		ERR("Error!!! Failed to get passpoint property");
		return FALSE;
	}

	if (g_variant_is_of_type(reply, G_VARIANT_TYPE_INT32)) {
		value = g_variant_get_int32(reply);
		if (value == TRUE)
			*enabled = 1;
		else
			*enabled = 0;

		result = TRUE;
	}

	g_variant_unref(reply);

	return result;
}

static gboolean netconfig_wifi_set_passpoint(gint32 enable)
{
	gint32 value = enable ? 1 : 0;
	gboolean result = FALSE;
	GVariant *input_args = NULL;

	input_args = g_variant_new_int32(value);

	result = netconfig_supplicant_invoke_dbus_interface_property_set(
			SUPPLICANT_IFACE_INTERFACE, "Passpoint", input_args, NULL);
	if (result == FALSE)
		ERR("Fail to set passpoint enable[%d]", enable);

	return result;
}
#endif

gboolean handle_get_passpoint(Wifi *wifi, GDBusMethodInvocation *context)
{
	gint32 enable = 0;
	g_return_val_if_fail(wifi != NULL, FALSE);

#if defined TIZEN_WLAN_PASSPOINT
	if (netconfig_wifi_get_passpoint(&enable)){
		wifi_complete_get_passpoint(wifi, context, enable);
		return TRUE;
	}
	wifi_complete_get_passpoint(wifi, context, enable);
	return FALSE;
#else
	enable = 0;
	wifi_complete_get_passpoint(wifi, context, enable);
	return TRUE;
#endif
}

gboolean handle_set_passpoint(Wifi *wifi, GDBusMethodInvocation *context, gint enable)
{
	gboolean result = FALSE;
	g_return_val_if_fail(wifi != NULL, FALSE);

#if defined TIZEN_WLAN_PASSPOINT
	result = netconfig_wifi_set_passpoint(enable);
	wifi_complete_set_passpoint(wifi, context);
	return result;
#else
	wifi_complete_set_passpoint(wifi, context);
	return result;
#endif
}
