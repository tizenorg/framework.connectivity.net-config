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

#ifndef __NETCONFIG_UTIL_H__
#define __NETCONFIG_UTIL_H__

#ifdef __cplusplus
extern "C" {
#endif

#include <glib.h>

#include "wifi.h"

#define NETCONFIG_ADD_FOUND_AP_NOTI		"add_found_ap_noti"
#define NETCONFIG_DEL_FOUND_AP_NOTI		"del_found_ap_noti"
#define NETCONFIG_ADD_PORTAL_NOTI		"add_portal_noti"
#define NETCONFIG_DEL_PORTAL_NOTI		"del_portal_noti"
#define NETCONFIG_TIZENMOBILEENV 		"/run/tizen-mobile-env"

#define MAX_SIZE_ERROR_BUFFER 256

#if defined TIZEN_WEARABLE
typedef enum {
	WC_POPUP_TYPE_SESSION_OVERLAPPED,
	WC_POPUP_TYPE_WIFI_CONNECTED,
	WC_POPUP_TYPE_CAPTIVE_PORTAL,
	WC_POPUP_TYPE_WIFI_RESTRICT
}netconfig_wcpopup_type_e;
#endif

GKeyFile *netconfig_keyfile_load(const char *pathname);
void netconfig_keyfile_save(GKeyFile *keyfile, const char *pathname);

void netconfig_start_timer_seconds(guint secs,
		gboolean(*callback) (gpointer), void *user_data, guint *timer_id);
void netconfig_start_timer(guint msecs,
		gboolean(*callback) (gpointer), void *user_data, guint *timer_id);
void netconfig_stop_timer(guint *timer_id);

void netconfig_wifi_enable_device_picker_test(void);
void netconfig_wifi_device_picker_service_start(void);
void netconfig_wifi_device_picker_service_stop(void);

gboolean netconfig_is_wifi_direct_on(void);
gboolean netconfig_is_wifi_tethering_on(void);

gboolean netconfig_interface_up(const char *ifname);
gboolean netconfig_interface_down(const char *ifname);

int netconfig_execute_file(const char *file_path, char *const args[], char *const env[]);
int netconfig_execute_clatd(const char *file_path, char *const args[]);
int netconfig_add_route_ipv6(gchar *ip_addr, gchar *interface, gchar *gateway, unsigned char prefix_len);
int netconfig_del_route_ipv6(gchar *ip_addr, gchar *interface, gchar *gateway, unsigned char prefix_len);
int netconfig_add_route_ipv4(gchar *ip_addr, gchar *subnet, gchar *interface, gint address_family);
int netconfig_del_route_ipv4(gchar *ip_addr, gchar *subnet, gchar *interface, gint address_family);

gboolean handle_launch_direct(Wifi *wifi, GDBusMethodInvocation *context);

gboolean netconfig_send_notification_to_net_popup(const char * noti, const char * data);
int netconfig_send_message_to_net_popup(const char *title,
		const char *content, const char *type, const char *ssid);
void netconfig_set_system_event(const char * sys_evt, const char * evt_key, const char * evt_val);
#if defined TIZEN_WEARABLE
int wc_launch_syspopup(netconfig_wcpopup_type_e type);
int wc_launch_popup(netconfig_wcpopup_type_e type);
#endif
void netconfig_set_vconf_int(const char * key, int value);
void netconfig_set_vconf_str(const char * key, const char * value);
char* netconfig_get_env(const char *key);
void netconfig_set_mac_address_from_file(void);

#ifdef __cplusplus
}
#endif

#endif /* __NETCONFIG_UTIL_H__ */
