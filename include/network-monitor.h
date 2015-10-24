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

#ifndef __NETCONFIG_NETWORK_MONITOR_H__
#define __NETCONFIG_NETWORK_MONITOR_H__

#ifdef __cplusplus
extern "C" {
#endif

#define ETH_REG_BMSR	   	0x01
#define BMSR_LINK_VALID		0x0004

#define SIOCGMIIPHY		0x8947		/* Get address of MII PHY in use. */
#define SIOCGMIIREG		0x8948		/* Read MII PHY register.	*/

struct _stMData {
    unsigned short phy_id;
    unsigned short reg_num;
    unsigned short val_in;
    unsigned short val_out;
};

int netconfig_ethernet_cable_plugin_status_check();
int netconfig_get_ethernet_cable_state(int *status);

#ifdef __cplusplus
}
#endif

#endif /* __NETCONFIG_NETWORK_MONITOR_H__ */
