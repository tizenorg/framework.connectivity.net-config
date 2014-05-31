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

#ifndef __NETCONFIG_NETWORK_STATE_H__
#define __NETCONFIG_NETWORK_STATE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <glib-object.h>
#include <dbus/dbus-glib.h>

G_BEGIN_DECLS

typedef struct NetconfigNetworkState	NetconfigNetworkState;
typedef struct NetconfigNetworkStateClass	NetconfigNetworkStateClass;

#define NETCONFIG_TYPE_NETWORK_STATE	( netconfig_network_state_get_type() )
#define NETCONFIG_NETWORK_STATE(obj)	( G_TYPE_CHECK_INSTANCE_CAST( (obj),NETCONFIG_TYPE_NETWORK_STATE, NetconfigNetworkState ) )
#define NETCONFIG_IS_NETWORK_STATE(obj)	(G_TYPE_CHECK_INSTANCE_TYPE( (obj), NETCONFIG_TYPE_NETWORK_STATE) )

#define NETCONFIG_NETWORK_STATE_CLASS(klass)	( G_TYPE_CHECK_CLASS_CAST( (klass), NETCONFIG_TYPE_NETWORK_STATE, NetconfigNetworkStateClass) )
#define NETCONFIG_IS_NETWORK_STATE_CLASS(klass)	( G_TYPE_CHECK_CLASS_TYPE( (klass), NETCONFIG_TYPE_NETWORK_STATE) )
#define NETCONFIG_NETWORK_STATE_GET_CLASS(obj)	( G_TYPE_INSTANCE_GET_CLASS( (obj), NETCONFIG_TYPE_NETWORK_STATE, NetconfigNetworkStateClass ) )

GType netconfig_network_state_get_type(void);

gpointer netconfig_network_state_create_and_init(DBusGConnection *conn);

const char *netconfig_get_default_profile(void);
const char *netconfig_get_default_ipaddress(void);
const char *netconfig_get_default_proxy(void);
const char *netconfig_wifi_get_connected_essid(const char *default_profile);
void netconfig_set_default_profile(const char *profile);

G_END_DECLS

#ifdef __cplusplus
}
#endif

#endif /* __NETCONFIG_NETWORK_STATE_H__ */
