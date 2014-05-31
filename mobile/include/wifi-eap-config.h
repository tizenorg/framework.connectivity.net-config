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

#ifndef __NETCONFIG_WIFI_EAP_CONFIG_H__
#define  __NETCONFIG_WIFI_EAP_CONFIG_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "wifi.h"

#define CONNMAN_STORAGEDIR "/var/lib/connman"

#define CONNMAN_CONFIG_FIELD_TYPE "Type"
#define CONNMAN_CONFIG_FIELD_NAME "Name"
#define CONNMAN_CONFIG_FIELD_SSID "SSID"
#define CONNMAN_CONFIG_FIELD_EAP_METHOD "EAP"
#define CONNMAN_CONFIG_FIELD_IDENTITY "Identity"
#define CONNMAN_CONFIG_FIELD_PASSPHRASE "Passphrase"
#define CONNMAN_CONFIG_FIELD_PHASE2 "Phase2"
#define CONNMAN_CONFIG_FIELD_CA_CERT_FILE "CACertFile"
#define CONNMAN_CONFIG_FIELD_CLIENT_CERT_FILE "ClientCertFile"
#define CONNMAN_CONFIG_FIELD_PVT_KEY_FILE "PrivateKeyFile"
#define CONNMAN_CONFIG_FIELD_PVT_KEY_PASSPHRASE "PrivateKeyPassphrase"

gboolean netconfig_iface_wifi_create_config(NetconfigWifi *wifi,
		GHashTable *fields, GError **error);
gboolean netconfig_iface_wifi_delete_config(NetconfigWifi *wifi,
		gchar *profile, GError **error);

#ifdef __cplusplus
}
#endif

#endif /* __NETCONFIG_WIFI_EAP_CONFIG_H__ */
