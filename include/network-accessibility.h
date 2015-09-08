/*
*  internet-accessibility check
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

#ifndef __NETCONFIG_NETWORK_ACCESSIBILITY_H__
#define __NETCONFIG_NETWORK_ACCESSIBILITY_H__

#ifdef __cplusplus
extern "C" {
#endif

void netconfig_check_internet_accessibility(void);
void netconfig_stop_internet_check(void);

/* Alert: Please do not use netconfig_get_internet_status() API to get the
 * status of Internet availability on general Wifi access points, as this module
 * primarily checks for Internet availability on portal enabled Wifi access
 * points, so we only check for below criteria in server's response to conclude
 * whether Internet is accessible.
 * 1) If the HTTP status != 302
 * 2) If the HTTP status != (200 with redirection),
*/
gboolean netconfig_get_internet_status();

#ifdef __cplusplus
}
#endif

#endif /* __NETCONFIG_NETWORK_ACCESSIBILITY_H__ */
