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

#include <aul.h>
#include <app.h>
#include <errno.h>
#include <vconf.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/wait.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <vconf-keys.h>
#include <syspopup_caller.h>

#include "log.h"
#include "util.h"
#include "neterror.h"
#include "wifi-state.h"

#define WC_POPUP_EXTRA_DATA_KEY	"http://samsung.com/appcontrol/data/connection_type"

static gboolean netconfig_device_picker_test = FALSE;

GKeyFile *netconfig_keyfile_load(const char *pathname)
{
	GKeyFile *keyfile = NULL;
	GError *error = NULL;

	keyfile = g_key_file_new();
	if (g_key_file_load_from_file(keyfile, pathname, 0, &error) != TRUE) {
		DBG("Unable to open %s, error %s", pathname, error->message);
		g_error_free(error);

		g_key_file_free(keyfile);
		keyfile = NULL;
	}

	return keyfile;
}

void netconfig_keyfile_save(GKeyFile *keyfile, const char *pathname)
{
	gsize size = 0;
	GError *error = NULL;
	gchar *keydata = NULL;
	gchar *needle = NULL, *directory = NULL;

	directory = g_strdup(pathname);
	needle = g_strrstr(directory, "/");

	if (needle != NULL)
		*needle = '\0';

	if (directory == NULL || (*directory) == '\0') {
		g_free(directory);
		return;
	}

	if (g_file_test(directory, G_FILE_TEST_IS_DIR) != TRUE) {
		if (g_mkdir_with_parents(directory,
				S_IRUSR | S_IWUSR | S_IXUSR) != 0) {
			g_free(directory);
			return;
		}
	}
	g_free(directory);

	keydata = g_key_file_to_data(keyfile, &size, &error);
	if (g_file_set_contents(pathname, keydata, size, &error) != TRUE) {
		DBG("Unable to save %s, error %s", pathname, error->message);
		g_error_free(error);
	}

	chmod(pathname, S_IRUSR | S_IWUSR);

	g_free(keydata);

	g_key_file_free(keyfile);
}

void netconfig_start_timer_seconds(guint secs,
		gboolean(*callback) (gpointer), void *user_data, guint *timer_id)
{
	guint t_id = 0;

	if (callback == NULL) {
		ERR("callback function is NULL");
		return;
	}

	if ((timer_id != NULL && *timer_id != 0)) {
		ERR("timer already is registered");
		return;
	}

	t_id = g_timeout_add_seconds(secs, callback, user_data);

	if (t_id == 0) {
		ERR("Can't add timer");
		return;
	}

	if (timer_id != NULL)
		*timer_id = t_id;
}

void netconfig_start_timer(guint msecs,
		gboolean(*callback) (gpointer), void *user_data, guint *timer_id)
{
	guint t_id = 0;

	INFO("Register timer with callback pointer (%p)", callback);

	if (callback == NULL) {
		ERR("callback function is NULL");
		return;
	}

	if ((timer_id != NULL && *timer_id != 0)) {
		ERR("timer already is registered");
		return;
	}

	t_id = g_timeout_add(msecs, callback, user_data);

	if (t_id == 0) {
		ERR("Can't add timer");
		return;
	}

	if (timer_id != NULL)
		*timer_id = t_id;
}

void netconfig_stop_timer(guint *timer_id)
{
	if (timer_id == NULL) {
		ERR("timer is NULL");
		return;
	}

	if (*timer_id != 0) {
		g_source_remove(*timer_id);
		*timer_id = 0;
	}
}

static gboolean __netconfig_test_device_picker()
{
	char *favorite_wifi_service = NULL;

	favorite_wifi_service = netconfig_wifi_get_favorite_service();
	if (favorite_wifi_service != NULL) {
		g_free(favorite_wifi_service);
		return FALSE;
	}

	return TRUE;
}

static void __netconfig_pop_device_picker(void)
{
#if defined TIZEN_WEARABLE
	int ret = 0;
	app_control_h	control = NULL;

	ret = app_control_create(&control);
	if (APP_CONTROL_ERROR_NONE != ret) {
		DBG("failed to create app control");
		return ;
	}

	app_control_add_extra_data(control, "viewtype", "scanlist");

	app_control_set_app_id(control, "org.tizen.wifi");
	ret = app_control_send_launch_request(control, NULL, NULL);
	if (APP_CONTROL_ERROR_NONE == ret)
		DBG("Launch request sent successfully");

	app_control_destroy(control);
#else
	bundle *b = NULL;
	int wifi_ug_state = 0;

	vconf_get_int(VCONFKEY_WIFI_UG_RUN_STATE, &wifi_ug_state);
	if (wifi_ug_state == VCONFKEY_WIFI_UG_RUN_STATE_ON_FOREGROUND)
		return;

	b = bundle_create();

	DBG("Launch Wi-Fi device picker");
	syspopup_launch("wifi-qs", b);

	bundle_free(b);
#endif
}

static gboolean __netconfig_wifi_try_device_picker(gpointer data)
{
	if (__netconfig_test_device_picker() == TRUE)
		__netconfig_pop_device_picker();

	return FALSE;
}

static guint __netconfig_wifi_device_picker_timer_id(gboolean is_set_method,
		guint timer_id)
{
	static guint netconfig_wifi_device_picker_service_timer = 0;

	if (is_set_method != TRUE)
		return netconfig_wifi_device_picker_service_timer;

	if (netconfig_wifi_device_picker_service_timer != timer_id)
		netconfig_wifi_device_picker_service_timer = timer_id;

	return netconfig_wifi_device_picker_service_timer;
}

static void __netconfig_wifi_device_picker_set_timer_id(guint timer_id)
{
	__netconfig_wifi_device_picker_timer_id(TRUE, timer_id);
}

static guint __netconfig_wifi_device_picker_get_timer_id(void)
{
	return __netconfig_wifi_device_picker_timer_id(FALSE, -1);
}

void netconfig_wifi_enable_device_picker_test(void)
{
	netconfig_device_picker_test = TRUE;
}

void netconfig_wifi_device_picker_service_start(void)
{
	const int NETCONFIG_WIFI_DEVICE_PICKER_INTERVAL = 700;
	guint timer_id = 0;

#if defined TIZEN_WEARABLE
	if (aul_app_is_running("org.tizen.wifi") > 0) {
		DBG("wifi app is running");
		return;
	}
#else
	int wifi_ug_state;

	if (netconfig_device_picker_test == TRUE)
		netconfig_device_picker_test = FALSE;
	else
		return;

	vconf_get_int(VCONFKEY_WIFI_UG_RUN_STATE, &wifi_ug_state);
	if (wifi_ug_state == VCONFKEY_WIFI_UG_RUN_STATE_ON_FOREGROUND)
		return;
#endif

	DBG("Register device picker timer with %d milliseconds",
			NETCONFIG_WIFI_DEVICE_PICKER_INTERVAL);

	netconfig_start_timer(NETCONFIG_WIFI_DEVICE_PICKER_INTERVAL,
			__netconfig_wifi_try_device_picker, NULL, &timer_id);

	__netconfig_wifi_device_picker_set_timer_id(timer_id);
}

void netconfig_wifi_device_picker_service_stop(void)
{
	guint timer_id = 0;

	timer_id = __netconfig_wifi_device_picker_get_timer_id();
	if (timer_id == 0)
		return;

	DBG("Clear device picker timer with timer_id %d", timer_id);

	netconfig_stop_timer(&timer_id);

	__netconfig_wifi_device_picker_set_timer_id(timer_id);
}

gboolean netconfig_is_wifi_direct_on(void)
{
#if defined TIZEN_P2P_ENABLE
	int wifi_direct_state = 0;

	vconf_get_int(VCONFKEY_WIFI_DIRECT_STATE, &wifi_direct_state);

	DBG("Wi-Fi direct mode %d", wifi_direct_state);
	return (wifi_direct_state != 0) ? TRUE : FALSE;
#else
	return FALSE;
#endif
}

gboolean netconfig_is_wifi_tethering_on(void)
{
#if defined TIZEN_TETHERING_ENABLE
	int wifi_tethering_state = 0;

	vconf_get_int(VCONFKEY_MOBILE_HOTSPOT_MODE, &wifi_tethering_state);

	DBG("Wi-Ti tethering mode %d", wifi_tethering_state);
	if (wifi_tethering_state & VCONFKEY_MOBILE_HOTSPOT_MODE_WIFI)
		return TRUE;
#endif
	return FALSE;
}

gboolean netconfig_interface_up(const char *ifname)
{
	int fd;
	struct ifreq ifr;

	fd = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return FALSE;

	memset(&ifr, 0, sizeof(ifr));
	g_strlcpy((char *)ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
		close(fd);
		return FALSE;
	}

	ifr.ifr_flags |= (IFF_UP | IFF_DYNAMIC);
	if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
		close(fd);
		return FALSE;
	}

	close(fd);

	DBG("Successfully activated wireless interface");
	return TRUE;
}

gboolean netconfig_interface_down(const char *ifname)
{
	int fd;
	struct ifreq ifr;

	fd = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (fd < 0)
		return FALSE;

	memset(&ifr, 0, sizeof(ifr));
	g_strlcpy((char *)ifr.ifr_name, ifname, sizeof(ifr.ifr_name));

	if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
		close(fd);
		return FALSE;
	}

	ifr.ifr_flags = (ifr.ifr_flags & ~IFF_UP) | IFF_DYNAMIC;
	if (ioctl(fd, SIOCSIFFLAGS, &ifr) < 0) {
		close(fd);
		return FALSE;
	}

	close(fd);

	DBG("Successfully de-activated wireless interface");
	return TRUE;
}

int netconfig_execute_file(const char *file_path,
		char *const args[], char *const envs[])
{
	pid_t pid = 0;
	int status = 0;
	int rv = 0;
	errno = 0;
	register unsigned int index = 0;

	while (args[index] != NULL) {
		DBG("%s", args[index]);
		index++;
	}

	if (!(pid = fork())) {
		DBG("pid(%d), ppid (%d)", getpid(), getppid());
		DBG("Inside child, exec (%s) command", file_path);

		errno = 0;
		if (execve(file_path, args, envs) == -1) {
			DBG("Fail to execute command (%s)", strerror(errno));
			exit(1);
		}
	} else if (pid > 0) {
		if (waitpid(pid, &status, 0) == -1)
			DBG("wait pid (%u) status (%d)", pid, status);

		if (WIFEXITED(status)) {
			rv = WEXITSTATUS(status);
			DBG("exited, status=%d", rv);
		} else if (WIFSIGNALED(status)) {
			DBG("killed by signal %d", WTERMSIG(status));
		} else if (WIFSTOPPED(status)) {
			DBG("stopped by signal %d", WSTOPSIG(status));
		} else if (WIFCONTINUED(status)) {
			DBG("continued");
		}

		return rv;
	}

	DBG("failed to fork(%s)", strerror(errno));
	return -EIO;
}

gboolean netconfig_iface_wifi_launch_direct(NetconfigWifi *wifi, GError **error)
{
#if defined TIZEN_P2P_ENABLE
	int ret = 0;
	DBG("Launch Wi-Fi direct daemon");

	const char *path = "/usr/bin/wifi-direct-server.sh";
	char *const args[] = { "wifi-direct-server.sh", "start", NULL };
	char *const envs[] = { NULL };

	ret = netconfig_execute_file(path, args, envs);
	if (ret < 0) {
		ERR("Failed to launch Wi-Fi direct daemon");

		netconfig_error_wifi_direct_failed(error);
		return FALSE;
	}

	return TRUE;
#else
	return FALSE;
#endif
}

gboolean netconfig_send_notification_to_net_popup(const char * noti, const char * ssid)
{
	int ret = 0;
	bundle *b;
	static gboolean is_found_noti_exists = FALSE;
	static gboolean is_portal_noti_exists = FALSE;

	if (noti == NULL) {
		ERR("Invalid notification");
		return FALSE;
	}

	if (g_strcmp0(noti, NETCONFIG_DEL_FOUND_AP_NOTI) == 0) {
		if (is_found_noti_exists == FALSE)
			return TRUE;

		is_found_noti_exists = FALSE;
	} else if (g_strcmp0(noti, NETCONFIG_ADD_FOUND_AP_NOTI) == 0) {
		if (is_found_noti_exists == TRUE)
			return TRUE;

		is_found_noti_exists = TRUE;
	} else if (g_strcmp0(noti, NETCONFIG_ADD_PORTAL_NOTI) == 0) {
		if (is_portal_noti_exists == TRUE)
			return TRUE;

		is_portal_noti_exists = TRUE;
	} else if (g_strcmp0(noti, NETCONFIG_DEL_PORTAL_NOTI) == 0) {
		if (is_portal_noti_exists == FALSE)
			return TRUE;

		is_portal_noti_exists = FALSE;
	}

	b = bundle_create();
	bundle_add(b, "_SYSPOPUP_TYPE_", noti);

	if (ssid != NULL) {
		DBG("ssid (%s)", ssid);
		bundle_add(b, "_AP_NAME_", ssid);
	}

	ret = aul_launch_app("net.netpopup", b);

	bundle_free(b);

	if (ret < 0) {
		ERR("Unable to launch noti-popup. Err = %d", ret);
		return FALSE;
	}

	DBG("Successfully sent notification (%s)", noti);
	return TRUE;
}

int netconfig_send_message_to_net_popup(const char *title,
		const char *content, const char *type, const char *ssid)
{
	int ret = 0;
	bundle *b = bundle_create();

	bundle_add(b, "_SYSPOPUP_TITLE_", title);
	bundle_add(b, "_SYSPOPUP_CONTENT_", content);
	bundle_add(b, "_SYSPOPUP_TYPE_", type);
	bundle_add(b, "_AP_NAME_", ssid);

	ret = aul_launch_app("net.netpopup", b);

	bundle_free(b);

	return ret;
}

void netconfig_set_vconf_int(const char * key, int value)
{
	int ret = 0;

	DBG("[%s: %d]", key, value);

	ret = vconf_set_int(key, value);
	if (ret != VCONF_OK)
		ERR("Failed to set");
}

void netconfig_set_vconf_str(const char * key, const char * value)
{
	int ret = 0;

	DBG("[%s: %s]", key, value);

	ret = vconf_set_str(key, value);
	if (ret != VCONF_OK)
		ERR("Failed to set");
}

char* netconfig_get_env(const char *key)
{
	FILE *fp;
	char buf[256], *entry=NULL, *value=NULL, *last;
	int len=0;

	if (!key)
		return NULL;

	fp = fopen(NETCONFIG_TIZENMOBILEENV, "r");
	if (!fp)
		return NULL;

	while (fgets(buf, sizeof(buf), fp)) {
		entry = buf;
		entry = strtok_r(entry, "=", &last);
		if (strstr(entry, key)) {
			entry = strtok_r(NULL, "\n", &last);
			if(entry){
				len = strlen(entry);
				value = (char*)malloc(len+1);
				g_strlcpy(value, entry, len+1);
			}
			else{
				value = (char*)malloc(sizeof(char));
				g_strlcpy(value, "\n", sizeof(char));
			}
			break;
		}
	}

	fclose(fp);
	return value;
}
