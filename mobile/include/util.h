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

#ifndef __NETCONFIG_UTIL_H__
#define __NETCONFIG_UTIL_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <glib.h>

#include "wifi.h"

GKeyFile *netconfig_keyfile_load(const char *pathname);
void netconfig_keyfile_save(GKeyFile *keyfile, const char *pathname);

void netconfig_start_timer_seconds(guint secs,
		gboolean(*callback) (gpointer), void *user_data, guint *timer_id);
void netconfig_start_timer(guint msecs,
		gboolean(*callback) (gpointer), void *user_data, guint *timer_id);
void netconfig_stop_timer(guint *timer_id);

void netconfig_wifi_device_picker_service_start(void);
void netconfig_wifi_device_picker_service_stop(void);

gboolean netconfig_is_wifi_direct_on(void);
gboolean netconfig_is_wifi_tethering_on(void);

gboolean netconfig_execute_file(const char *file_path,
		char *const args[], char *const env[]);

gboolean netconfig_iface_wifi_launch_direct(NetconfigWifi *wifi, GError **error);
void netconfig_set_wifi_mac_address(void);

void netconfig_add_wifi_found_notification(void);
void netconfig_del_wifi_found_notification(void);

#ifdef __cplusplus
}
#endif

#endif /* __NETCONFIG_UTIL_H__ */
