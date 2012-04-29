/*
 * Network Configuration Module
 *
 * Copyright (c) 2000 - 2012 Samsung Electronics Co., Ltd. All rights reserved.
 *
 * Contact: Danny JS Seo <S.Seo@samsung.com>
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

#ifndef __NETCONFIG_WIFI_H__
#define  __NETCONFIG_WIFI_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <glib.h>
#include <glib-object.h>
#include <dbus/dbus-glib.h>

G_BEGIN_DECLS

typedef struct NetconfigWifi NetconfigWifi;
typedef struct NetconfigWifiClass NetconfigWifiClass;

#define NETCONFIG_TYPE_WIFI	(netconfig_wifi_get_type())
#define NETCONFIG_WIFI(obj)	(G_TYPE_CHECK_INSTANCE_CAST((obj), NETCONFIG_TYPE_WIFI, NetconfigWifi))
#define NETCONFIG_IS_WIFI(obj)	(G_TYPE_CHECK_INSTANCE_TYPE((obj), NETCONFIG_TYPE_WIFI))
#define NETCONFIG_WIFI_CLASS(klass)	(G_TYPE_CHECK_CLASS_CAST((klass), NETCONFIG_TYPE_WIFI, NetconfigWifiClass))
#define NETCONFIG_IS_WIFI_CLASS(klass)	(G_TYPE_CHECK_CLASS_TYPE((klass), NETCONFIG_TYPE_WIFI))
#define NETCONFIG_WIFI_GET_CLASS(obj)	(G_TYPE_INSTANCE_GET_CLASS((obj), NETCONFIG_TYPE_WIFI, NetconfigWifiClass))

#define VCONF_WIFI_LAST_POWER_ON_STATE "db/wifi/LastPowerOnState"

enum netconfig_wifi_power_state {
	WIFI_POWER_OFF = 0x00,
	WIFI_POWER_ON = 0x01,
};

enum netconfig_wifi_power_triggering_state {
	WIFI_NON_OF_TRIGGERING = 0x01,

	WIFI_ACTIVATING = 0x02,
	WIFI_DEACTIVATING = 0x03,
};

GType netconfig_wifi_get_type(void);


gpointer netconfig_wifi_create_and_init(DBusGConnection *conn);

gboolean netconfig_wifi_remove_driver(void);

gboolean netconfig_wifi_enable_technology(void);
gboolean netconfig_wifi_disable_technology(void);
void netconfig_wifi_set_power_triggering_state(
		enum netconfig_wifi_power_triggering_state state);
enum netconfig_wifi_power_triggering_state
		netconfig_wifi_get_power_triggering_state(void);

gboolean netconfig_iface_wifi_load_driver(NetconfigWifi *wifi, GError **error);
gboolean netconfig_iface_wifi_remove_driver(NetconfigWifi *wifi, GError **error);

G_END_DECLS

#ifdef __cplusplus
}
#endif

#endif /* __NETCONFIG_WIFI_H__ */
