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
#include <vconf.h>

#include "log.h"
#include "wifi-tel-intf.h"

#define TAPI_HANDLE_MAX	2

#define SIM_SLOT_DUAL 2
#define SIM_SLOT_SINGLE 1

#define VCONF_TELEPHONY_DEFAULT_DATA_SERVICE	"db/telephony/dualsim/default_data_service"
#define DEFAULT_DATA_SERVICE_SIM1 0
#define DEFAULT_DATA_SERVICE_SIM2 1

static TapiHandle *tapi_handle_dual[TAPI_HANDLE_MAX+1];
static TapiHandle *tapi_handle = NULL;

static int _check_current_sim()
{
#if defined TIZEN_WEARABLE
	return -1;
#else
	int current_sim = 0;
	int sim_slot_count = 0;

	if ((vconf_get_int(VCONFKEY_TELEPHONY_SIM_SLOT_COUNT, &sim_slot_count) != 0)
		|| sim_slot_count == SIM_SLOT_SINGLE) {
		ERR("failed to get sim slot count (%d)", sim_slot_count);
		return -1;
	}

	if (vconf_get_int(VCONF_TELEPHONY_DEFAULT_DATA_SERVICE, &current_sim) != 0) {
		ERR("failed to get default data service = %d\n", current_sim);
		return 0;
	}

	DBG("default data service [SIM%d]", current_sim);
	return current_sim;
#endif
}

TapiHandle * netconfig_tel_init(void)
{
	char **cp_list = NULL;
	int current_sim = _check_current_sim();

	if (current_sim < 0) {
		if (tapi_handle == NULL) {
			tapi_handle = tel_init(NULL);
			if (tapi_handle == NULL)
				ERR("tel_init() Failed - modem %d", current_sim);
		}
		return tapi_handle;
	} else {
		if (tapi_handle_dual[current_sim] == NULL) {
			cp_list = tel_get_cp_name_list();
			if (!cp_list) {
				ERR("tel_get_cp_name_list() Failed");
				return NULL;
			}

			tapi_handle_dual[current_sim] = tel_init(cp_list[current_sim]);
			if (tapi_handle_dual[current_sim] == NULL)
				ERR("tel_init() Failed - modem %d", current_sim);

			g_strfreev(cp_list);
		}
		return tapi_handle_dual[current_sim];
	}
}

void netconfig_tel_deinit(void)
{
	int current_sim = 	_check_current_sim();

	if (current_sim < 0){
		if (tapi_handle)
			tel_deinit(tapi_handle);

		tapi_handle = NULL;
	} else {
		unsigned int i = 0;
		while (tapi_handle_dual[i]) {
			tel_deinit(tapi_handle_dual[i]);
			tapi_handle_dual[i] = NULL;
			i++;
		}
	}
}

