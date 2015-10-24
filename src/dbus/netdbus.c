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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "log.h"
#include "netdbus.h"

#define DBUS_PARAM_TYPE_STRING		"string"
#define DBUS_PARAM_TYPE_INT16		"int16"
#define DBUS_PARAM_TYPE_UINT16		"uint16"
#define DBUS_PARAM_TYPE_INT32		"int32"
#define DBUS_PARAM_TYPE_UINT32		"uint32"
#define DBUS_PARAM_TYPE_INT64		"int64"
#define DBUS_PARAM_TYPE_UINT64		"uint64"
#define DBUS_PARAM_TYPE_DOUBLE		"double"
#define DBUS_PARAM_TYPE_BYTE		"byte"
#define DBUS_PARAM_TYPE_BOOLEAN		"boolean"
#define DBUS_PARAM_TYPE_OBJECT_PATH	"objpath"
#define DBUS_PARAM_TYPE_VARIANT		"variant"
#define DBUS_PARAM_TYPE_ARRAY		"array"

static GDBusObjectManagerServer *manager_server_wifi = NULL;
static GDBusObjectManagerServer *manager_server_state = NULL;
static GDBusObjectManagerServer *manager_server_statistics = NULL;
static guint owner_id = 0;
static got_name_cb g_callback = NULL;

struct gdbus_conn_data {
	GDBusConnection *connection;
	int conn_ref_count;
	GCancellable *cancellable;
};

static struct gdbus_conn_data gconn_data = {NULL, 0, NULL};

GDBusObjectManagerServer *netdbus_get_wifi_manager(void)
{
	return manager_server_wifi;
}

GDBusObjectManagerServer *netdbus_get_state_manager(void)
{
	return manager_server_state;
}

GDBusObjectManagerServer *netdbus_get_statistics_manager(void)
{
	return manager_server_statistics;
}

GDBusConnection *netdbus_get_connection(void)
{
	return gconn_data.connection;
}

GCancellable *netdbus_get_cancellable(void)
{
	return gconn_data.cancellable;
}

void netconfig_gdbus_pending_call_ref(void)
{
	g_object_ref(gconn_data.connection);

	__sync_fetch_and_add(&gconn_data.conn_ref_count, 1);
}

void netconfig_gdbus_pending_call_unref(void)
{
	if (gconn_data.conn_ref_count < 1)
		return;

	g_object_unref(gconn_data.connection);

	if (__sync_sub_and_fetch(&gconn_data.conn_ref_count, 1) < 1) {
		/* TODO: Check this
		 * gconn_data.connection = NULL;
		 */
	}
}

int _create_gdbus_call(GDBusConnection *conn)
{
	if (gconn_data.connection != NULL) {
		ERR("Connection already set");
		return -1;
	}

	gconn_data.connection = conn;
	if (gconn_data.connection == NULL) {
		ERR("Failed to connect to the D-BUS daemon");
		return -1;
	}

	gconn_data.cancellable = g_cancellable_new();

	return 0;
}

gboolean netconfig_is_cellular_internet_profile(const char *profile)
{
	const char internet_suffix[] = "_1";
	char *suffix = NULL;

	if (profile == NULL)
		return FALSE;

	if (g_str_has_prefix(profile, CONNMAN_CELLULAR_SERVICE_PROFILE_PREFIX)
			== TRUE) {
		suffix = strrchr(profile, '_');
		if (g_strcmp0(suffix, internet_suffix) == 0)
			return TRUE;
	}

	return FALSE;
}

gboolean netconfig_is_cellular_profile(const char *profile)
{
	if (profile == NULL)
		return FALSE;

	return g_str_has_prefix(profile, CONNMAN_CELLULAR_SERVICE_PROFILE_PREFIX);
}

gboolean netconfig_is_wifi_profile(const char *profile)
{
	if (profile == NULL)
		return FALSE;

	return g_str_has_prefix(profile, CONNMAN_WIFI_SERVICE_PROFILE_PREFIX);
}

gboolean netconfig_is_ethernet_profile(const char *profile)
{
	if (profile == NULL)
		return FALSE;

	return g_str_has_prefix(profile, CONNMAN_ETHERNET_SERVICE_PROFILE_PREFIX);
}

gboolean netconfig_is_bluetooth_profile(const char *profile)
{
	if (profile == NULL)
		return FALSE;

	return g_str_has_prefix(profile, CONNMAN_BLUETOOTH_SERVICE_PROFILE_PREFIX);
}

gboolean netconfig_invoke_dbus_method_nonblock(const char *dest, const char *path,
		const char *interface_name, const char *method, GVariant *params,
		GAsyncReadyCallback notify_func)
{
	GDBusConnection *connection = NULL;

	DBG("[GDBUS Async] %s %s %s", interface_name, method, path);

	connection = netdbus_get_connection();
	if (connection == NULL) {
		ERR("Failed to get gdbus connection");
		return FALSE;
	}

	g_dbus_connection_call(connection,
			dest,
			path,
			interface_name,
			method,
			params,
			NULL,
			G_DBUS_CALL_FLAGS_NONE,
			NETCONFIG_DBUS_REPLY_TIMEOUT,
			netdbus_get_cancellable(),
			(GAsyncReadyCallback) notify_func,
			NULL);

	return TRUE;
}

GVariant *netconfig_invoke_dbus_method(const char *dest, const char *path,
		const char *interface_name, const char *method, GVariant *params)
{

	GError *error = NULL;
	GVariant *reply = NULL;
	GDBusConnection *connection;

	connection = netdbus_get_connection();
	if (connection == NULL) {
		ERR("Failed to get GDBusconnection");
		return reply;
	}

	reply = g_dbus_connection_call_sync(
			connection,
			dest,
			path,
			interface_name,
			method,
			params,
			NULL,
			G_DBUS_CALL_FLAGS_NONE,
			NETCONFIG_DBUS_REPLY_TIMEOUT,
			netdbus_get_cancellable(),
			&error);

	if (reply == NULL) {
		if (error != NULL) {
			ERR("g_dbus_connection_call_sync() failed"
						"error [%d: %s]", error->code, error->message);
			g_error_free(error);
		} else {
			ERR("g_dbus_connection_call_sync() failed");
		}

		return NULL;
	}

	return reply;
}

static void _got_bus_cb(GDBusConnection *conn, const gchar *name,
		gpointer user_data)
{
	_create_gdbus_call(conn);
}

static void _got_name_cb(GDBusConnection *conn, const gchar *name,
		gpointer user_data)
{
	INFO("Got gdbus name: [%s] and gdbus connection: [%p]", name, conn);

	if (g_callback != NULL) {
		g_callback();
	}
}

static void _lost_name_cb(GDBusConnection *conn, const gchar *name,
		gpointer user_data)
{
	/* May service name is already in use */
	ERR("_lost_name_cb [%s]", name);

	/* The result of DBus name request is only permitted,
	 *  such as DBUS_REQUEST_NAME_REPLY_PRIMARY_OWNER.
	 */
	exit(2);
}

int setup_gdbus(got_name_cb cb)
{
	g_callback = cb;

	manager_server_wifi = g_dbus_object_manager_server_new(NETCONFIG_WIFI_PATH);
	if (manager_server_wifi == NULL) {
		ERR("Manager server for WIFI_PATH not created.");
		exit(1);
	}

	manager_server_state = g_dbus_object_manager_server_new(NETCONFIG_NETWORK_STATE_PATH);
	if (manager_server_state == NULL) {
		ERR("Manager server for STATE_PATH not created.");
		exit(1);
	}

	manager_server_statistics = g_dbus_object_manager_server_new(NETCONFIG_NETWORK_STATISTICS_PATH);
	if (manager_server_statistics == NULL) {
		ERR("Manager server for STATISTICS_PATH not created.");
		exit(1);
	}

	owner_id = g_bus_own_name(G_BUS_TYPE_SYSTEM, NETCONFIG_SERVICE,
							  G_BUS_NAME_OWNER_FLAGS_NONE,
							  _got_bus_cb, _got_name_cb, _lost_name_cb,
							  NULL, NULL);
	if (!owner_id) {
		ERR("Could not get system bus!");
		return -EIO;
	}

	INFO("Got system bus!");
	return 0;
}

void cleanup_gdbus(void)
{
	g_bus_unown_name(owner_id);
	g_object_unref(manager_server_wifi);
	g_object_unref(manager_server_state);
	g_object_unref(manager_server_statistics);
}
