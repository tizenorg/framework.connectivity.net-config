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

#include <stdio.h>
#include <unistd.h>
#include <vconf.h>
#include <vconf-keys.h>

#include "log.h"
#include "wifi.h"
#include "util.h"
#include "netdbus.h"
#include "neterror.h"
#include "netconfig.h"
#include "wifi-power.h"
#include "wifi-state.h"
#include "wifi-ssid-scan.h"
#include "wifi-eap.h"
#include "wifi-eap-config.h"
#include "wifi-background-scan.h"
#include "wifi-agent.h"

#include "netconfig-iface-wifi-glue.h"


#define PROP_DEFAULT		FALSE
#define PROP_DEFAULT_STR	NULL

enum {
	PROP_O,
	PROP_WIFI_CONN,
	PROP_WIFI_PATH,
};

enum {
	SIG_WIFI_DRIVER,
	SIG_LAST
};

struct NetconfigWifiClass {
	GObjectClass parent;

	/* method and signals */
	void (*driver_loaded) (NetconfigWifi *wifi, gchar *mac);
};

struct NetconfigWifi {
	GObject parent;

	/* member variable */
	DBusGConnection *conn;
	gchar *path;
};

static guint32 signals[SIG_LAST] = { 0, };

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
		wifi->conn = g_value_get_boxed(value);
		INFO("wifi(%p) set conn(%p)", wifi, wifi->conn);
		break;
	}

	case PROP_WIFI_PATH:
	{
		if (wifi->path)
			g_free(wifi->path);

		wifi->path = g_value_dup_string(value);
		INFO("wifi(%p) path(%s)", wifi, wifi->path);

		break;
	}

	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID(object, prop_id, pspec);
	}
}

static void netconfig_wifi_init(NetconfigWifi *wifi)
{
	DBG("wifi initialize");

	wifi->conn = NULL;
	wifi->path = g_strdup(PROP_DEFAULT_STR);
}

static void netconfig_wifi_class_init(NetconfigWifiClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS(klass);

	DBG("class initialize");

	object_class->get_property = __netconfig_wifi_gobject_get_property;
	object_class->set_property = __netconfig_wifi_gobject_set_property;

	/* DBus register */
	dbus_g_object_type_install_info(NETCONFIG_TYPE_WIFI,
			&dbus_glib_netconfig_iface_wifi_object_info);

	/* property */
	g_object_class_install_property(object_class, PROP_WIFI_CONN,
			g_param_spec_boxed("conn", "CONNECTION", "DBus connection",
				DBUS_TYPE_G_CONNECTION,
				G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	g_object_class_install_property(object_class, PROP_WIFI_PATH,
			g_param_spec_string("path", "PATH", "Object Path",
				PROP_DEFAULT_STR,
				G_PARAM_READWRITE | G_PARAM_CONSTRUCT_ONLY));

	/* signal */
	signals[SIG_WIFI_DRIVER] = g_signal_new("driver-loaded",
			G_OBJECT_CLASS_TYPE(klass),
			G_SIGNAL_RUN_LAST,
			G_STRUCT_OFFSET(NetconfigWifiClass,
				driver_loaded),
			NULL, NULL,
			g_cclosure_marshal_VOID__STRING,
			G_TYPE_NONE, 1, G_TYPE_STRING);
}

gpointer netconfig_wifi_create_and_init(DBusGConnection *conn)
{
	GObject *object;

	g_return_val_if_fail(conn != NULL, NULL);

	object = g_object_new(NETCONFIG_TYPE_WIFI, "conn", conn, "path",
			NETCONFIG_WIFI_PATH, NULL);

	INFO("create wifi(%p)", object);

	dbus_g_connection_register_g_object(conn, NETCONFIG_WIFI_PATH, object);

	INFO("wifi(%p) register DBus path(%s)", object, NETCONFIG_WIFI_PATH);

	netconfig_wifi_power_configuration();
	netconfig_wifi_init_bgscan();

	return object;
}
