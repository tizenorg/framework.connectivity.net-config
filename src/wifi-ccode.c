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

#include <glib.h>
#include <errno.h>
#include <vconf.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <vconf-keys.h>

#include "log.h"
#include "util.h"
#include "netsupplicant.h"

#define CCODE_CONFIG_FILE					"/etc/wifi/ccode.conf"
#define MCC_TO_ISO_MAP_GROUP_NAME			"mcc_iso_map"
#define DEFAULT_CCODE		"GB"

/* Structure to send private command to Wi-Fi driver */
typedef struct netconfig_wifi_priv_cmd {
	char *buf;
	int used_len;
	int total_len;
} netconfig_wifi_priv_cmd;

static char *__netconfig_get_mcc(void)
{
	int plmn = 0;
	char mcc[4] = { 0, };
	const int mcc_length = 3;

	if (vconf_get_int(VCONFKEY_TELEPHONY_PLMN, &plmn) != 0) {
		ERR("OPERATION_FAILED");
		return NULL;
	}

	g_snprintf(mcc, mcc_length + 1, "%d", plmn);

	return g_strdup(mcc);
}

static char *__netconfig_wifi_ccode_get_csc(void)
{
	char *iso = NULL;

	iso = vconf_get_str(VCONFKEY_CSC_COUNTRY_ISO);
	if (iso == NULL)
		ERR("Failed to get CSC country ISO code");

	return iso;
}

/*
 * Get the iso code and rev number from Broadcom config file with mcc
 * Input: valid keyfile of the config file, valid mcc
 * Return: the ISO on success
 *         NULL on failure
 */
static gchar *__netconfig_wifi_ccode_get_iso_from_mcc(
		GKeyFile *keyfile, char *mcc)
{
	gchar *iso = NULL;

	if (keyfile == NULL || mcc == NULL)
		return NULL;

	iso = g_key_file_get_string(keyfile, MCC_TO_ISO_MAP_GROUP_NAME, mcc, NULL);
	if (iso == NULL)
		ERR("Failed to get ISO with mcc %s", mcc);

	return iso;
}

void netconfig_wifi_ccode_init(void)
{
	char *iso = NULL;
	char *mcc = NULL;
	GKeyFile *keyfile = NULL;
	struct ifreq ifr;
	char buf[248] = { 0, }; /* Max driver command size is 248 */
	netconfig_wifi_priv_cmd priv_cmd;
	int ret = 0;
	int ioctl_sock = 0;
	size_t buf_len;

	DBG("Init Wi-Fi country code");

	keyfile = netconfig_keyfile_load(CCODE_CONFIG_FILE);
	if (keyfile == NULL) {
		DBG("Unable to get ISO code... Default ISO=[%s]", DEFAULT_CCODE);
		goto SET_COUNTRY_REV;
	}

	mcc = __netconfig_get_mcc();
	iso = __netconfig_wifi_ccode_get_iso_from_mcc(keyfile, mcc);

	if (iso == NULL) {
		/*
		 * Unable to get the ISO code using mcc.
		 * Lets get it from CSC.
		 */
		iso = __netconfig_wifi_ccode_get_csc();
	}


SET_COUNTRY_REV:

	if (mcc != NULL)
		g_free(mcc);

	if (keyfile != NULL)
		g_key_file_free(keyfile);

	if (iso == NULL) {
		g_snprintf(buf, sizeof(buf), "COUNTRY %s", DEFAULT_CCODE);
	} else {
		char *iso_upper = g_ascii_strup(iso, -1);
		g_snprintf(buf, sizeof(buf), "COUNTRY %s", iso_upper);
		g_free(iso_upper);
		g_free(iso);
	}

	memset(&ifr, 0, sizeof(struct ifreq));
	g_strlcpy((char *)ifr.ifr_name, WIFI_IFNAME, IFNAMSIZ);

	DBG("CCode command: [%s]", buf);
	memset(&priv_cmd, 0, sizeof(priv_cmd));
	buf_len = strlen(buf);
	priv_cmd.buf = buf;
	priv_cmd.used_len = buf_len;
	priv_cmd.total_len = buf_len;
	ifr.ifr_data = (char *)&priv_cmd;

	ioctl_sock = socket(PF_INET, SOCK_DGRAM, 0);
	if (ioctl_sock < 0) {
		DBG("socket(PF_INET,SOCK_DGRAM) failed");
		return;
	}

	ret = ioctl(ioctl_sock, SIOCDEVPRIVATE + 1, &ifr);
	if (ret < 0)
		ERR("Fail to issue private commands: %d %s", ret, strerror(errno));

	close(ioctl_sock);
}
