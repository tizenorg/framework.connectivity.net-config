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
#include "log.h"
#include "cellular-state.h"

static cellular_service_state_e cellular_service_state = NETCONFIG_CELLULAR_UNKNOWN;

static GSList *notifier_list = NULL;

static void _cellular_state_changed(cellular_service_state_e state)
{
	GSList *list;

	for (list = notifier_list; list; list = list->next) {
		cellular_state_notifier *notifier = list->data;

		if (notifier->cellular_state_changed != NULL)
			notifier->cellular_state_changed(state, notifier->user_data);
	}
}

void cellular_state_set_service_state(cellular_service_state_e new_state)
{
	cellular_service_state_e old_state = cellular_service_state;

	if (old_state == new_state)
		return;

	cellular_service_state = new_state;
	DBG("Cellular state %d ==> %d", old_state, new_state);
	_cellular_state_changed(new_state);
}

cellular_service_state_e cellular_state_get_service_state(void)
{
	return cellular_service_state;
}

void cellular_state_notifier_register(cellular_state_notifier *notifier)
{
	DBG("register notifier");

	notifier_list = g_slist_append(notifier_list, notifier);
}

void cellular_state_notifier_unregister(cellular_state_notifier *notifier)
{
	DBG("un-register notifier");

	notifier_list = g_slist_remove_all(notifier_list, notifier);
}

void cellular_state_notifier_cleanup(void)
{
	g_slist_free_full(notifier_list, NULL);
}
