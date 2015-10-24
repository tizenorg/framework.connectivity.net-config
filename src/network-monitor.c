/*
 * Network Configuration Module
 *
 * Copyright (c) 2014 Samsung Electronics Co., Ltd. All rights reserved.
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

#include "log.h"
#include "util.h"
#include "netdbus.h"
#include "network-monitor.h"
#include "network-state.h"
#include "wifi-power.h"

#include <arpa/inet.h>
#include <net/route.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <vconf.h>
#include <vconf-keys.h>

/* Check send notification status */
static gboolean g_chk_eth_send_notification = FALSE;

int netconfig_ethernet_cable_plugin_status_check()
{
	struct ifreq ifr;
	int soketfd = -1;
	int error = 0;
	int ret = 0;
	struct _stMData *mdata;
	struct timeval tv;
	char error_buf[MAX_SIZE_ERROR_BUFFER] = {};

	soketfd = socket(PF_INET, SOCK_DGRAM | SOCK_CLOEXEC, 0);
	if (soketfd < 0) {
		ERR("Failed to create socket");
		return -errno;
	}

	/* Set Timeout for IOCTL Call */
	tv.tv_sec = 1;
	tv.tv_usec = 0;

	if (setsockopt(soketfd, SOL_SOCKET, SO_RCVTIMEO, (char *)&tv,
			sizeof(struct timeval)) < 0) {

		strerror_r(errno, error_buf, MAX_SIZE_ERROR_BUFFER);
		ERR("Failed to set socket option : [%d] [%s]", -errno, error_buf);
		goto done;
	}

	memset(&ifr, 0, sizeof(ifr));
	g_strlcpy(ifr.ifr_name, "eth0", IFNAMSIZ);
	if (ioctl(soketfd, SIOCGMIIPHY, &ifr) < 0){
		error = -errno;
		strerror_r(errno, error_buf, MAX_SIZE_ERROR_BUFFER);
		ERR("SIOCGMIIPHY on eth0 failed : [%d] [%s]", errno, error_buf);
		goto done;
	}

	mdata = (struct _stMData *)&ifr.ifr_data;
	mdata->reg_num = ETH_REG_BMSR;

	if (ioctl(soketfd, SIOCGMIIREG, &ifr) < 0){
		error = -errno;
		strerror_r(errno, error_buf, MAX_SIZE_ERROR_BUFFER);
		ERR("SIOCGMIIREG on %s failed , [%d] [%s] ", ifr.ifr_name,errno,error_buf);
		goto done;
	}
	ret = mdata->val_out;
	ret = ret & BMSR_LINK_VALID;

	if(ret == 4) {
		if(!g_chk_eth_send_notification)
			netconfig_network_notify_ethernet_cable_state("ATTACHED");
		g_chk_eth_send_notification = TRUE;
	} else if (ret == 0) {
		if(g_chk_eth_send_notification)
			netconfig_network_notify_ethernet_cable_state("DETACHED");
		g_chk_eth_send_notification = FALSE;
	}
	error = 0;
done:
	close(soketfd);
	return error;
}

int netconfig_get_ethernet_cable_state(int *status)
{
	int error = 0;
	if(status == NULL) {
		DBG("Error !!! Invalid Parameter\n");
		return -1;
	}

	if((error = netconfig_ethernet_cable_plugin_status_check()) != 0) {
		DBG("Error !!! Failed to check ethernet cable status [%d]\n", error);
		return -1;
	}

	if(g_chk_eth_send_notification == TRUE)
		*status = 1;		/* Ethernet cable Attached */
	else
		*status = 0;		/* Ethernet cable Deattached */
	return 0;
}
