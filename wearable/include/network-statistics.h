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
#include <dbus/dbus-glib.h>

#include "wifi-state.h"

G_BEGIN_DECLS

typedef struct NetconfigNetworkStatistics	NetconfigNetworkStatistics;
typedef struct NetconfigNetworkStatisticsClass	NetconfigNetworkStatisticsClass;

#define NETCONFIG_TYPE_NETWORK_STATISTICS \
	( netconfig_network_statistics_get_type() )
#define NETCONFIG_NETWORK_STATISTICS(obj) \
	( G_TYPE_CHECK_INSTANCE_CAST((obj), NETCONFIG_TYPE_NETWORK_STATISTICS, \
			NetconfigNetworkStatistics) )
#define NETCONFIG_IS_NETWORK_STATISTICS(obj) \
	( G_TYPE_CHECK_INSTANCE_TYPE((obj), NETCONFIG_TYPE_NETWORK_STATISTICS) )

#define NETCONFIG_NETWORK_STATISTICS_CLASS(klass) \
	( G_TYPE_CHECK_CLASS_CAST((klass), NETCONFIG_TYPE_NETWORK_STATISTICS, \
			NetconfigNetworkStatisticsClass) )
#define NETCONFIG_IS_NETWORK_STATISTICS_CLASS(klass) \
	( G_TYPE_CHECK_CLASS_TYPE((klass), NETCONFIG_TYPE_NETWORK_STATISTICS) )
#define NETCONFIG_NETWORK_STATISTICS_GET_CLASS(obj) \
	( G_TYPE_INSTANCE_GET_CLASS((obj), NETCONFIG_TYPE_NETWORK_STATISTICS, \
			NetconfigNetworkStatisticsClass) )

GType netconfig_network_statistics_get_type(void);

gpointer netconfig_network_statistics_create_and_init(
		DBusGConnection *connection);

G_END_DECLS

gboolean netconfig_iface_network_statistics_get_wifi_total_tx_bytes(
		NetconfigNetworkStatistics *network_statistics,
		guint64 *total_bytes, GError **error);
gboolean netconfig_iface_network_statistics_get_wifi_total_rx_bytes(
		NetconfigNetworkStatistics *network_statistics,
		guint64 *total_bytes, GError **error);
gboolean netconfig_iface_network_statistics_get_wifi_last_tx_bytes(
		NetconfigNetworkStatistics *network_statistics,
		guint64 *last_bytes, GError **error);
gboolean netconfig_iface_network_statistics_get_wifi_last_rx_bytes(
		NetconfigNetworkStatistics *network_statistics,
		guint64 *last_bytes, GError **error);

gboolean netconfig_iface_network_statistics_reset_cellular_total_tx_bytes(
		NetconfigNetworkStatistics *network_statistics, GError **error);
gboolean netconfig_iface_network_statistics_reset_cellular_total_rx_bytes(
		NetconfigNetworkStatistics *network_statistics, GError **error);
gboolean netconfig_iface_network_statistics_reset_cellular_last_tx_bytes(
		NetconfigNetworkStatistics *network_statistics, GError **error);
gboolean netconfig_iface_network_statistics_reset_cellular_last_rx_bytes(
		NetconfigNetworkStatistics *network_statistics, GError **error);

gboolean netconfig_iface_network_statistics_reset_wifi_total_tx_bytes(
		NetconfigNetworkStatistics *network_statistics, GError **error);
gboolean netconfig_iface_network_statistics_reset_wifi_total_rx_bytes(
		NetconfigNetworkStatistics *network_statistics, GError **error);
gboolean netconfig_iface_network_statistics_reset_wifi_last_tx_bytes(
		NetconfigNetworkStatistics *network_statistics, GError **error);
gboolean netconfig_iface_network_statistics_reset_wifi_last_rx_bytes(
		NetconfigNetworkStatistics *network_statistics, GError **error);

gboolean netconfig_wifi_get_bytes_statistics(guint64 *tx, guint64 *rx);
void netconfig_wifi_statistics_update_powered_off(void);

#ifdef __cplusplus
}
#endif

#endif /* __NETWORK_STATISTICS_H__ */
