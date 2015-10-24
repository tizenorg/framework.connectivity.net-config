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

#ifndef __NETCONFIG_WIFI_H__
#define __NETCONFIG_WIFI_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <glib.h>
#include <gio/gio.h>
#include <glib-object.h>

#include "generated-code.h"

#define WIFI_STORAGEDIR			"/var/lib/wifi"
#define WIFI_CERT_STORAGEDIR	"/var/lib/wifi/cert"
#define CONNMAN_STORAGEDIR		"/var/lib/connman"

void wifi_object_create_and_init(void);
void wifi_object_deinit(void);

Wifi *get_wifi_object(void);

#ifdef __cplusplus
}
#endif

#endif /* __NETCONFIG_WIFI_H__ */
