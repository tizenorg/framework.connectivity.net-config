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

#include <stdio.h>
#include <unistd.h>
#include <vconf.h>
#include <vconf-keys.h>

#include "log.h"
#include "wifi.h"
#include "util.h"
#include "netdbus.h"
#include "neterror.h"
#include "wifi-eap.h"
#include "wifi-wps.h"
#include "wifi-power.h"
#include "wifi-agent.h"
#include "wifi-firmware.h"
#include "wifi-ssid-scan.h"
#include "wifi-passpoint.h"
#include "wifi-eap-config.h"
#include "wifi-background-scan.h"

#include "netconfig-iface-wifi-glue.h"

#define PROP_DEFAULT		FALSE
#define PROP_DEFAULT_STR	NULL

enum {
	PROP_O,
	PROP_WIFI_CONN,
	PROP_WIFI_PATH,
};

struct NetconfigWifiClass {
	GObjectClass parent;
};

struct NetconfigWifi {
	GObject parent;

	DBusGConnection *connection;
	gchar *path;
};

G_DEFINE_TYPE(NetconfigWifi, netconfig_wifi, G_TYPE_OBJECT);

static void __netconfig_wifi_gobject_get_property(GObject *object, guint prop_id,
		GValue *value, GParamSpec *pspec)
{
	return;
}

static void __netconfig_wifi_gobject_set_property(GObject *object, guint prop_id,
		const GValue *value, GParamSpec *pspec)
{
	NetconfigWifi *wifi = NETCONFIG_WIFI(object);

	switch (prop_id) {
	case PROP_WIFI_CONN:
	{
		wifi->connection = g_value_get_boxed(value);
		break;
	}

	case PROP_WIFI_PATH:
	{
		if (wifi->path)
			g_free(wifi->path);

		wifi->path = g_value_dup_string(value);
		break;
	}

	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
	}
}

static void netconfig_wifi_init(NetconfigWifi *wifi)
{
	wifi->connection = NULL;
	wifi->path = g_strdup(PROP_DEFAULT_STR);
}

static void netconfig_wifi_class_init(NetconfigWifiClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS(klass);

	object_class->get_property = __netconfig_wifi_gobject_get_property;
	object_class->set_property = __netconfig_wifi_gobject_set_property;

	/* DBus register */
	dbus_g_object_type_install_info(NETCONFIG_TYPE_WIFI,
			&dbus_glib_netconfig_iface_wifi_object_info);

	/* property */
	g_object_class_install_property(object_class, PROP_WIFI_CONN,
			g_param_spec_boxed("connection", "CONNECTION", "DBus connection",
				DBUS_TYPE_G_CONNECTION,
				G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property(object_class, PROP_WIFI_PATH,
			g_param_spec_string("path", "Path", "Object path",
				PROP_DEFAULT_STR,
				G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));
}

gpointer netconfig_wifi_create_and_init(DBusGConnection *connection)
{
	GObject *object;

	g_return_val_if_fail(connection != NULL, NULL);

	object = g_object_new(NETCONFIG_TYPE_WIFI, "connection", connection, "path",
			NETCONFIG_WIFI_PATH, NULL);

	dbus_g_connection_register_g_object(connection, NETCONFIG_WIFI_PATH, object);

	netconfig_wifi_power_initialize();

	return object;
}
