/*
 *  Internet-accessibility check
 *
 * Copyright 2012  Samsung Electronics Co., Ltd
 *
 * Licensed under the Flora License, Version 1.1 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.tizenopensource.org/license
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <net/if.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/inotify.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/route.h>
#include <glib.h>
#include <gio/gio.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include "log.h"
#include "util.h"
#include "wifi-agent.h"
#include "netsupplicant.h"
#include "network-state.h"
#include "network-accessibility.h"

#define BUF_SIZE 2048
#define NETCONFIG_INTERNET_CHECK_TIMEOUT	3

enum netconfig_internet_check_state {
	INTERNET_CHECK_STATE_NONE,
	INTERNET_CHECK_STATE_DNS_CHECK,
	INTERNET_CHECK_STATE_PACKET_CHECK
};

struct internet_params {
	int fd;
	char *addr;
	int port;
	guint transport_watch;
	guint send_watch;
	gboolean header_done;
	gboolean request_started;
	GCancellable *resolv_cancel;
};

const static char* url_list[] = {
	 "www.google.com",
	 "www.msn.com",
	 "www.yahoo.com",
	 "m.google.com",
	 "www.amazon.com",
	 "www.youtube.com"
 };

static guint timer_id = 0;
static const char *proxy_addr = NULL;
static gboolean perform_recheck = TRUE;
struct internet_params *net_params = NULL;
static gboolean is_internet_available = FALSE;
const static int url_list_num = 6;
static int url_index = 0;
static char * redirect_url1 = NULL;
static char * redirect_url2 = NULL;
static enum netconfig_internet_check_state check_state =
		INTERNET_CHECK_STATE_NONE;

static void __netconfig_connect_sockets(void);
static void __internet_check_state(
		enum netconfig_internet_check_state state);

gboolean netconfig_get_internet_status()
{
	return is_internet_available;
}

static void __netconfig_update_internet_status(unsigned char *reply)
{
	/* If the HTTP response is either 302 or 200 with redirection,
	 * then no Internet is available */
	char *temp = NULL;
	is_internet_available = FALSE;

	if (NULL != reply) {
		if ((NULL != g_strrstr((char*)reply, "HTTP/1.1 200")) &&
				(NULL != g_strrstr((char*)reply, "auth action"))) {
			DBG("200 OK but redirection found so:: Internet is un-available");
		} else if (NULL != g_strrstr((char*)reply, "HTTP/1.1 302")) {
			DBG("302:: Internet is un-available");
		} else if ((temp = g_strrstr((char*)reply, "Location:")) != NULL) {
			char * location = strtok(temp, "\r");
			if (location != NULL) {
				DBG("%s", location);
				if (redirect_url1 == NULL)
					redirect_url1 = g_strdup(location + strlen("Location: "));
				else if (redirect_url2 == NULL)
					redirect_url2 = g_strdup(location + strlen("Location: "));

				if (redirect_url1 != NULL && redirect_url2 != NULL) {
					DBG("[%s] [%s]", redirect_url1, redirect_url2);
					if (g_strcmp0(redirect_url1, redirect_url2) == 0) {
						DBG("Internet is un-available(Redirection to Error page)");
						is_internet_available = FALSE;
					} else
						is_internet_available = TRUE;

					g_free(redirect_url1);
					g_free(redirect_url2);
					redirect_url1 = NULL;
					redirect_url2 = NULL;
				}
			}
		} else {
			is_internet_available = TRUE;
			DBG("Internet is available");
		}
	}

	if (is_internet_available == TRUE)
		netconfig_send_notification_to_net_popup(NETCONFIG_DEL_PORTAL_NOTI, NULL);
}

static gboolean __netconfig_data_activity_timeout(gpointer data)
{
	DBG("Timer timed-out");
	enum netconfig_internet_check_state prev_state =
					(enum netconfig_internet_check_state)data;
	INFO("Prev_state: state=%d (1:dns check / 2:packet check)",prev_state);

	if (net_params == NULL)
		return FALSE;

	if (TRUE == perform_recheck && prev_state != INTERNET_CHECK_STATE_NONE) {
		perform_recheck = FALSE;
		if (prev_state == INTERNET_CHECK_STATE_DNS_CHECK) {
			net_params->request_started = FALSE;
			netconfig_check_internet_accessibility();
		} else /* (state == NETCONFIG_DATA_ACTIVITY_STATE_PACKET_CHECK) */
			__netconfig_connect_sockets();
		return FALSE;
	} else {
		perform_recheck = TRUE;
		__internet_check_state(INTERNET_CHECK_STATE_NONE);
	}

	return FALSE;
}

static void __netconfig_internet_check_timer_stop(void)
{
	if (timer_id != 0)
		netconfig_stop_timer(&timer_id);
}

static void __netconfig_internet_check_timer_start(
		enum netconfig_internet_check_state state)
{
	static guint timeout = 0;
	if (timer_id != 0) {
		DBG("netconfig_data_activity_timer is already running, so stop it");
		__netconfig_internet_check_timer_stop();
	}

	if (state == INTERNET_CHECK_STATE_NONE)
		return;
	else if (state == INTERNET_CHECK_STATE_DNS_CHECK)
		timeout = NETCONFIG_INTERNET_CHECK_TIMEOUT;
	else if (state == INTERNET_CHECK_STATE_PACKET_CHECK)
		timeout = NETCONFIG_INTERNET_CHECK_TIMEOUT;

	netconfig_start_timer_seconds(timeout,
			__netconfig_data_activity_timeout,
			(void *)state,
			&timer_id);
}

static void __internet_check_state(
		enum netconfig_internet_check_state state)
{
	if (check_state == state)
		return;

	INFO("state change (%d) -> (%d)", check_state, state);
	switch (state) {
	case INTERNET_CHECK_STATE_DNS_CHECK:
		__netconfig_internet_check_timer_start(state);
		break;
	case INTERNET_CHECK_STATE_PACKET_CHECK:
		if (check_state == INTERNET_CHECK_STATE_DNS_CHECK)
			__netconfig_internet_check_timer_stop();

		__netconfig_internet_check_timer_start(state);
		break;
	case INTERNET_CHECK_STATE_NONE:
		switch (check_state) {
		case INTERNET_CHECK_STATE_DNS_CHECK:
		case INTERNET_CHECK_STATE_PACKET_CHECK:
			__netconfig_internet_check_timer_stop();
			netconfig_stop_internet_check();
			break;
		default:
			break;
		}
		break;
	}
	check_state = state;
}

void netconfig_stop_internet_check(void)
{
	if (net_params == NULL)
		return;

	net_params->header_done = FALSE;
	net_params->request_started = FALSE;

	if (net_params->resolv_cancel != NULL) {
		g_cancellable_cancel(net_params->resolv_cancel);
		g_object_unref(net_params->resolv_cancel);
		net_params->resolv_cancel = NULL;
	}

	if (net_params->transport_watch > 0) {
		g_source_remove(net_params->transport_watch);
		net_params->transport_watch = 0;
	}

	if (net_params->send_watch > 0) {
		g_source_remove(net_params->send_watch);
		net_params->send_watch = 0;
	}

	if (net_params->fd > 0) {
		close(net_params->fd);
		net_params->fd = -1;
	}

	if (net_params->addr != NULL) {
		g_free(net_params->addr);
		net_params->addr = NULL;
	}

	g_free(net_params);
	net_params = NULL;
}

static gboolean __received_data_event(GIOChannel *channel,
		GIOCondition condition, gpointer data)
{
	int n, fd;
	unsigned char buf[BUF_SIZE] = { 0, };

	if (net_params == NULL)
		return FALSE;

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP))
		goto cleanup;

	fd = g_io_channel_unix_get_fd(channel);
	if (fd < 0)
		goto cleanup;

	n = read(fd, buf, BUF_SIZE - 1);
	DBG("Received %d bytes[%s]", n, buf);
	buf[BUF_SIZE - 1] = '\0';

	if (n < 0) {
		ERR("read failed. %s", strerror(errno));

		goto cleanup;
	} else if (n == 0) {
		INFO("connection closed");

		goto cleanup;
	}

	/* We got data from server successfully */
	__netconfig_update_internet_status(buf);
	__internet_check_state(INTERNET_CHECK_STATE_NONE);

	return TRUE;

cleanup:
	/* Fail to get data from server */
	__internet_check_state(INTERNET_CHECK_STATE_NONE);

	return FALSE;
}

static gboolean __send_data_event(GIOChannel *channel,
		GIOCondition condition, gpointer data)
{
	int n, fd;
	const char *request_data =
			"GET /index.html HTTP/1.1\r\nHost: connman.net\r\n\r\n";

	if (net_params == NULL)
		return FALSE;

	if (condition & (G_IO_NVAL | G_IO_ERR | G_IO_HUP))
		goto cleanup;

	fd = g_io_channel_unix_get_fd(channel);
	if (fd < 0)
		goto cleanup;

	/* We don't need to send anymore. Just return here.*/
	/* Socket will be closed received part*/
	if (net_params->header_done == TRUE)
		return FALSE;

	n = send(fd, request_data, strlen(request_data), 0);
	DBG("Sent %d bytes", n);

	if (n < 0) {
		ERR("send failed. %s", strerror(errno));

		goto cleanup;
	} else if (n == 0) {
		INFO("connection closed");

		goto cleanup;
	}

	net_params->header_done = TRUE;
	return TRUE;

cleanup:
	__internet_check_state(INTERNET_CHECK_STATE_NONE);

	return FALSE;
}

static void __netconfig_connect_sockets(void)
{
	GIOFlags flags;
	struct sockaddr_in addr;
	GIOChannel *channel = NULL;
	int sock;

	if (net_params == NULL || net_params->addr == NULL)
		return;

	sock = socket(PF_INET, SOCK_STREAM, 0);
	if (sock < 0)
		goto cleanup;

	if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE,
			WIFI_IFNAME, strlen(WIFI_IFNAME) + 1) < 0) {
		ERR("Bind to device error");
		close(sock);
		goto cleanup;
	}

	memset(&addr, 0, sizeof(struct sockaddr_in));
	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = inet_addr(net_params->addr);
	addr.sin_port = htons(net_params->port);

	/* Register Watch */
	channel = g_io_channel_unix_new(sock);

	flags = g_io_channel_get_flags(channel);
	g_io_channel_set_flags(channel, flags | G_IO_FLAG_NONBLOCK, NULL);
	g_io_channel_set_encoding(channel, NULL, NULL);
	g_io_channel_set_buffered(channel, FALSE);

	if (connect(sock, (struct sockaddr *)&addr,
			sizeof(struct sockaddr_in)) < 0) {
		if (errno != EINPROGRESS) {
			INFO("connect fail");
			close(sock);
			goto cleanup;
		}
	}

	DBG("Connect successful");

	net_params->fd = sock;
	net_params->transport_watch = g_io_add_watch(channel,
			(GIOCondition) (G_IO_IN | G_IO_HUP | G_IO_NVAL | G_IO_ERR),
			(GIOFunc) __received_data_event, NULL);
	net_params->send_watch = g_io_add_watch(channel,
			(GIOCondition) (G_IO_OUT | G_IO_HUP | G_IO_NVAL | G_IO_ERR),
			(GIOFunc) __send_data_event, NULL);

	__internet_check_state(INTERNET_CHECK_STATE_PACKET_CHECK);
	return;

	cleanup:
	__internet_check_state(INTERNET_CHECK_STATE_NONE);
}

static void __netconfig_obtain_host_ip_addr_cb(GObject *src,
		GAsyncResult *res,
		gpointer user_data)
{
	GList *list, *cur;
	GInetAddress *addr;
	gchar *str_addr;

	if (net_params == NULL)
		return;

	if (check_state == INTERNET_CHECK_STATE_NONE)
		return;

	list = g_resolver_lookup_by_name_finish((GResolver *)src, res, NULL);
	if (!list) {
		INFO("no data");
		goto cleanup;
	}

	for (cur = list; cur; cur = cur->next) {
		addr = cur->data;
		str_addr = g_inet_address_to_string(addr);
		if (!str_addr)
			continue;

		if (net_params != NULL) {
			g_free(net_params->addr);
			net_params->addr = str_addr;
		}

		g_object_unref(cur->data);
		break;
	}

	g_list_free(list);

	if (net_params->addr == NULL)
		goto cleanup;

	net_params->port = 80;
	__netconfig_connect_sockets();

	return;

cleanup:
	__internet_check_state(INTERNET_CHECK_STATE_NONE);
}

gboolean __netconfig_obtain_host_ip_addr(void)
{
	char *host, *addr, *port;

	if (net_params == NULL)
		return FALSE;

	if (net_params->request_started == TRUE)
		return FALSE;
	else
		net_params->request_started = TRUE;

	if (net_params->addr != NULL)
		return TRUE;

	proxy_addr = netconfig_get_default_proxy();
	DBG("Proxy(%s)", proxy_addr);

	if (++url_index >= url_list_num)
		url_index = 0;

	DBG("addr (%s)", url_list[url_index]);

	/* FIXME: domain proxy should be resolved */
	if (proxy_addr == NULL) {
		GResolver *r = NULL;
		net_params->resolv_cancel = g_cancellable_new();
		r = g_resolver_get_default();

		g_resolver_lookup_by_name_async(r,
				url_list[url_index],
				net_params->resolv_cancel,
				__netconfig_obtain_host_ip_addr_cb,
				NULL);
		__internet_check_state(INTERNET_CHECK_STATE_DNS_CHECK);

		g_object_unref(r);
		return FALSE;
	} else {
		host = g_strdup(proxy_addr);
		if (host == NULL)
			goto cleanup;

		addr = strtok(host, ":");
		if (addr == NULL)
			goto cleanup;

		port = strrchr(proxy_addr, ':');
		if (port == NULL)
			goto cleanup;
		else {
			char *end;
			int tmp = strtol(port + 1, &end, 10);

			if (*end == '\0') {
				*port = '\0';
				net_params->port = tmp;
			}
		}
		g_free(net_params->addr);
		net_params->addr = g_strdup(addr);

		g_free(host);
	}
	return TRUE;

cleanup:
	g_free(host);
	netconfig_stop_internet_check();

	return FALSE;
}

void netconfig_check_internet_accessibility(void)
{
	DBG("::Entry");

	if (net_params == NULL) {
		net_params = g_try_malloc0(sizeof(struct internet_params));
		if (net_params == NULL)
			return;
		net_params->fd = -1;
	}

	if ((check_state != INTERNET_CHECK_STATE_NONE) ||
			(net_params->request_started == TRUE)) {
		DBG("Older query in progress");
		return;
	}

	is_internet_available = FALSE;

	/* If the host IP is resolved, directly go for connecting to sockets*/
	if (__netconfig_obtain_host_ip_addr() == TRUE) {
		__netconfig_connect_sockets();
	}
}
