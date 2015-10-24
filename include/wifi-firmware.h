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

#ifndef __NETCONFIG_WIFI_FIRMWARE_H__
#define __NETCONFIG_WIFI_FIRMWARE_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <glib.h>
#include "wifi.h"

enum netconfig_wifi_firmware {
	NETCONFIG_WIFI_OFF		= 0x00,
	NETCONFIG_WIFI_STA		= 0x01,
	NETCONFIG_WIFI_P2P		= 0x02,
	NETCONFIG_WIFI_SOFTAP	= 0x03,
};

int netconfig_wifi_firmware(enum netconfig_wifi_firmware type, gboolean enable);

gboolean handle_start(WifiFirmware *firmware, GDBusMethodInvocation *context, const gchar *device);
gboolean handle_stop(WifiFirmware *firmware, GDBusMethodInvocation *context, const gchar *device);

#ifdef __cplusplus
}
#endif

#endif /* __NETCONFIG_WIFI_FIRMWARE_H__ */
