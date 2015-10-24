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

#ifndef __NETCONFIG_WIFI_CONFIG_H__
#define __NETCONFIG_WIFI_CONFIG_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "wifi.h"

// Configuration Field key
#define WIFI_CONFIG_NAME				"Name"
#define WIFI_CONFIG_SSID				"SSID"
#define WIFI_CONFIG_PASSPHRASE		"Passphrase"
#define WIFI_CONFIG_SECURITY_TYPE		"Security"
#define WIFI_CONFIG_FAVORITE			"Favorite"
#define WIFI_CONFIG_AUTOCONNECT		"AutoConnect"
#define WIFI_CONFIG_HIDDEN				"Hidden"
#define WIFI_CONFIG_FAILURE			"Failure"
#define WIFI_CONFIG_PROXYADDRESS		"ProxyAddress"
#define WIFI_CONFIG_PROXY_METHOD		"Proxy.Method"
#define WIFI_CONFIG_PROXY_SERVER		"Proxy.Servers"
#define WIFI_CONFIG_EAP_ANONYMOUS_IDENTITY			"AnonymousIdentity"
#define WIFI_CONFIG_EAP_CACERT			"CACertFile"
#define WIFI_CONFIG_EAP_CLIENTCERT			"ClientCertFile"
#define WIFI_CONFIG_EAP_PRIVATEKEY		"PrivateKeyFile"
#define WIFI_CONFIG_EAP_IDENTITY		"Identity"
#define WIFI_CONFIG_EAP_TYPE		"EapType"
#define WIFI_CONFIG_EAP_AUTH_TYPE	"EapAuthType"
#define WIFI_CONFIG_EAP_SUBJECT_MATCH	"SubjectMatch"

gboolean	wifi_config_get_config_id(const gchar *service_profile, gchar **config_id);
gboolean	wifi_config_remove_configuration(const gchar *config_id);

gboolean	handle_get_config_ids(Wifi *wifi, GDBusMethodInvocation *context);
gboolean	handle_load_configuration(Wifi *wifi, GDBusMethodInvocation *context, const gchar *config_id);
gboolean	handle_save_configuration(Wifi *wifi, GDBusMethodInvocation *context, const gchar *config_id, GVariant *configuration);
gboolean	handle_load_eap_configuration(Wifi *wifi, GDBusMethodInvocation *context, const gchar *config_id);
gboolean	handle_save_eap_configuration(Wifi *wifi, GDBusMethodInvocation *context, const gchar *config_id, GVariant *configuration);
gboolean	handle_remove_configuration(Wifi *wifi, GDBusMethodInvocation *context, const gchar *config_id);
gboolean	handle_set_config_field(Wifi *wifi, GDBusMethodInvocation *context, const gchar *config_id, const gchar *key, const gchar *value);
gboolean	handle_get_config_passphrase(Wifi *wifi, GDBusMethodInvocation *context, const gchar *config_id);

#ifdef __cplusplus
}
#endif

#endif /* __NETCONFIG_WIFI_CONFIG_H */
