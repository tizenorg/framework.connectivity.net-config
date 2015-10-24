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

#ifndef __NETWORK_STATISTICS_H__
#define __NETWORK_STATISTICS_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <glib-object.h>

#include "wifi-state.h"

gboolean	netconfig_wifi_get_bytes_statistics(guint64 *tx, guint64 *rx);
void		netconfig_wifi_statistics_update_powered_off(void);

void statistics_object_create_and_init(void);
void statistics_object_deinit(void);

#ifdef __cplusplus
}
#endif

#endif /* __NETWORK_STATISTICS_H__ */
