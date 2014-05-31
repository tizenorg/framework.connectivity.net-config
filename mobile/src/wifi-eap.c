/*
 * Network Configuration Module
 *
 * Copyright (c) 2012-2013 Samsung Electronics Co., Ltd. All rights reserved.
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

#include <tapi_common.h>
#include <TapiUtility.h>
#include <ITapiSim.h>

#include "log.h"
#include "util.h"
#include "netdbus.h"
#include "neterror.h"

#define SIM_RAND_DATA_LEN 16
#define SIM_AUTH_MAX_RESP_DATA_LEN 128
#define SIM_AUTH_SRES_LEN 4
#define SIM_AUTH_KC_LEN 8

#define AKA_RAND_DATA_LEN 16
#define AKA_AUTN_DATA_LEN 16
#define AKA_AUTH_RES_MAX_LEN 16
#define AKA_AUTH_RES_MIN_LEN 4
#define AKA_AUTH_CK_LEN 16
#define AKA_AUTH_IK_LEN 16

struct wifii_authentication_data {
	int auth_result;
	int resp_length;
	int authentication_key_length;
	int cipher_length;
	int integrity_length;
	char *resp_data;
	char *authentication_key;
	char *cipher_data;
	char *integrity_data;
};

TapiHandle *tapi_handle = NULL;
static struct wifii_authentication_data *wifi_authdata;

static void *__netconfig_wifi_free_wifi_authdata(struct wifii_authentication_data *data)
{
	if (data) {
		if (data->resp_data)
			g_free(data->resp_data);
		if (data->authentication_key)
			g_free(data->authentication_key);
		if (data->cipher_data)
			g_free(data->cipher_data);
		if (data->integrity_data)
			g_free(data->integrity_data);

		g_free(data);
		data = NULL;
	}

	return NULL;
}

static void __netconfig_tapi_init()
{
	tapi_handle = tel_init(NULL);
}

static void __netconfig_tapi_deinit()
{
	tel_deinit(tapi_handle);
	tapi_handle = NULL;

	wifi_authdata = __netconfig_wifi_free_wifi_authdata(wifi_authdata);
}

static gboolean __netconfig_wifi_get_sim_imsi(DBusGMethodInvocation *context)
{
	DBG(" ");

	int ret;
	GError *error = NULL;
	TelSimImsiInfo_t imsi_info;
	char *imsi;

	if (tapi_handle == NULL)
		__netconfig_tapi_init();

	ret = tel_get_sim_imsi(tapi_handle, &imsi_info);
	if (ret != TAPI_API_SUCCESS) {
		ERR("Failed tel_get_sim_imsi() : [%d]", ret);
		netconfig_error_fail_get_imsi(&error);
		dbus_g_method_return_error(context, error);
		return FALSE;
	}

	imsi = g_strdup_printf("%s%s%s", imsi_info.szMcc, imsi_info.szMnc, imsi_info.szMsin);

	dbus_g_method_return(context, imsi);
	g_free(imsi);

	return TRUE;
}

void __netconfig_response_sim_authentication(TapiHandle *handle, int result, void *data, void *user_data)
{
	DBG(" ");

	if (wifi_authdata != NULL)
		wifi_authdata = __netconfig_wifi_free_wifi_authdata(wifi_authdata);

	wifi_authdata = g_try_new0(struct wifii_authentication_data, 1);

	TelSimAuthenticationResponse_t *auth_resp = (TelSimAuthenticationResponse_t *) data;
	if (auth_resp == NULL) {
		ERR("the auth response is NULL");
		wifi_authdata->auth_result = -1;
		return;
	} else {
		wifi_authdata->auth_result = auth_resp->auth_result;
	}

	if (auth_resp->auth_result == TAPI_SIM_AUTH_NO_ERROR) {
		wifi_authdata->resp_length = auth_resp->resp_length;
		wifi_authdata->authentication_key_length = auth_resp->authentication_key_length;

		if (wifi_authdata->resp_data != NULL)
			g_free(wifi_authdata->resp_data);
		wifi_authdata->resp_data = g_strdup(auth_resp->resp_data);

		if (wifi_authdata->authentication_key != NULL)
			g_free(wifi_authdata->authentication_key);
		wifi_authdata->authentication_key = g_strdup(auth_resp->authentication_key);
	} else {
		ERR("the result error for sim auth : [%d]", auth_resp->auth_result);
		wifi_authdata->resp_length = 0;
		wifi_authdata->authentication_key_length = 0;
	}
}

void __netconfig_response_aka_authentication(TapiHandle *handle, int result, void *data, void *user_data)
{
	DBG(" ");

	if (wifi_authdata != NULL)
		wifi_authdata = __netconfig_wifi_free_wifi_authdata(wifi_authdata);

	wifi_authdata = g_try_new0(struct wifii_authentication_data, 1);

	TelSimAuthenticationResponse_t *auth_resp = (TelSimAuthenticationResponse_t *) data;
	if (auth_resp == NULL) {
		ERR("the auth response is NULL");
		wifi_authdata->auth_result = -1;
		return;
	} else {
		wifi_authdata->auth_result = auth_resp->auth_result;
	}

	if (auth_resp->auth_result == TAPI_SIM_AUTH_NO_ERROR) {
		wifi_authdata->resp_length = auth_resp->resp_length;
		wifi_authdata->cipher_length = auth_resp->cipher_length;
		wifi_authdata->integrity_length = auth_resp->integrity_length;

		if (wifi_authdata->resp_data != NULL)
			g_free(wifi_authdata->resp_data);
		wifi_authdata->resp_data = g_strdup(auth_resp->resp_data);

		if (wifi_authdata->cipher_data != NULL)
			g_free(wifi_authdata->cipher_data);
		wifi_authdata->cipher_data = g_strdup(auth_resp->cipher_data);

		if (wifi_authdata->integrity_data != NULL)
			g_free(wifi_authdata->integrity_data);
		wifi_authdata->integrity_data = g_strdup(auth_resp->integrity_data);
	} else {
		ERR("the result error for aka auth : [%d]", auth_resp->auth_result);
		if (auth_resp->auth_result == TAPI_SIM_AUTH_SQN_FAILURE ||
					auth_resp->auth_result == TAPI_SIM_AUTH_SYNCH_FAILURE) {
			wifi_authdata->resp_length = auth_resp->resp_length;

			if (wifi_authdata->resp_data != NULL)
				g_free(wifi_authdata->resp_data);
			wifi_authdata->resp_data = g_strdup(auth_resp->resp_data);
		}
	}
}

static gboolean __netconfig_wifi_req_sim_auth(GArray *rand_data, GError **error)
{
	DBG(" ");

	int i;
	int ret;
	TelSimAuthenticationData_t auth_data;

	if (rand_data->len != SIM_RAND_DATA_LEN) {
		ERR("wrong rand data len : [%d]", rand_data->len);
		netconfig_error_fail_req_sim_auth_wrong_param(error);
		return FALSE;
	}

	if ((ret = g_array_get_element_size(rand_data)) != 1) {
		ERR("wrong rand data size : [%d]", ret);
		netconfig_error_fail_req_sim_auth_wrong_param(error);
		return FALSE;
	}

	memset(&auth_data, 0, sizeof(auth_data));
	auth_data.auth_type = TAPI_SIM_AUTH_TYPE_GSM;
	auth_data.rand_length = SIM_RAND_DATA_LEN;
	for (i=0; i<rand_data->len; i++)
		auth_data.rand_data[i] = g_array_index(rand_data, guint8, i);

	if (tapi_handle == NULL)
		__netconfig_tapi_init();

	ret = tel_req_sim_authentication(tapi_handle, &auth_data, __netconfig_response_sim_authentication, NULL);
	if (ret != TAPI_API_SUCCESS) {
		ERR("Failed tel_req_sim_authentication() : [%d]", ret);
		netconfig_error_fail_req_sim_auth(error);
		return FALSE;
	}

	return TRUE;
}

static gboolean __netconfig_wifi_req_aka_auth(GArray *rand_data, GArray *autn_data, GError **error)
{
	DBG(" ");

	int i;
	int ret;
	TelSimAuthenticationData_t auth_data;

	if (rand_data->len != AKA_RAND_DATA_LEN) {
		ERR("wrong rand data len : [%d]", rand_data->len);
		netconfig_error_fail_req_sim_auth_wrong_param(error);
		return FALSE;
	}

	if (autn_data->len != AKA_AUTN_DATA_LEN) {
		ERR("wrong autn data len : [%d]", autn_data->len);
		netconfig_error_fail_req_sim_auth_wrong_param(error);
		return FALSE;
	}

	if ((ret = g_array_get_element_size(rand_data)) != 1) {
		ERR("wrong rand data size : [%d]", ret);
		netconfig_error_fail_req_sim_auth_wrong_param(error);
		return FALSE;
	}

	if ((ret = g_array_get_element_size(autn_data)) != 1) {
		ERR("wrong autn data size : [%d]", ret);
		netconfig_error_fail_req_sim_auth_wrong_param(error);
		return FALSE;
	}

	memset(&auth_data, 0, sizeof(auth_data));
	auth_data.auth_type = TAPI_SIM_AUTH_TYPE_3G;
	auth_data.rand_length = AKA_RAND_DATA_LEN;
	auth_data.autn_length = AKA_AUTN_DATA_LEN;
	for (i=0; i<rand_data->len; i++)
		auth_data.rand_data[i] = g_array_index(rand_data, guint8, i);
	for (i=0; i<autn_data->len; i++)
		auth_data.autn_data[i] = g_array_index(autn_data, guint8, i);

	if (tapi_handle == NULL)
		__netconfig_tapi_init();

	ret = tel_req_sim_authentication(tapi_handle, &auth_data, __netconfig_response_aka_authentication, NULL);
	if (ret != TAPI_API_SUCCESS) {
		ERR("Failed tel_req_sim_authentication() : [%d]", ret);
		netconfig_error_fail_req_sim_auth(error);
		return FALSE;
	}

	return TRUE;
}

static gboolean __netconfig_wifi_get_sim_authdata(DBusGMethodInvocation *context)
{
	DBG(" ");

	GArray *array = NULL;
	GError *error = NULL;

	if (wifi_authdata == NULL) {
		DBG("the status error : no response yet");
		netconfig_error_fail_get_sim_auth_delay(&error);
		dbus_g_method_return_error(context, error);
		return FALSE;
	}

	if (wifi_authdata->auth_result == TAPI_SIM_AUTH_NO_ERROR) {
		if (wifi_authdata->resp_length == SIM_AUTH_SRES_LEN &&
				wifi_authdata->authentication_key_length == SIM_AUTH_KC_LEN) {
			array = g_array_sized_new(FALSE, FALSE, sizeof(guchar), SIM_AUTH_SRES_LEN+SIM_AUTH_KC_LEN);
			g_array_append_vals(array, wifi_authdata->resp_data, SIM_AUTH_SRES_LEN);
			g_array_append_vals(array, wifi_authdata->authentication_key, SIM_AUTH_KC_LEN);
			dbus_g_method_return(context, array);
			g_array_free (array, TRUE);
		} else {
			ERR("auth data length is wrong, SRES = [%d], Kc = [%d]",
					wifi_authdata->resp_length, wifi_authdata->authentication_key_length);

			netconfig_error_fail_get_sim_auth_wrong_data(&error);
			dbus_g_method_return_error(context, error);
			__netconfig_tapi_deinit();
			return FALSE;
		}
	} else {
		ERR("failed auth result = [%d]", wifi_authdata->auth_result);
		netconfig_error_fail_get_sim_auth_wrong_data(&error);
		dbus_g_method_return_error(context, error);
		__netconfig_tapi_deinit();
		return FALSE;
	}

	__netconfig_tapi_deinit();
	return TRUE;
}

static gboolean __netconfig_wifi_get_aka_authdata(DBusGMethodInvocation *context)
{
	DBG(" ");

	GArray *array = NULL;
	GError *error = NULL;
	guchar res_len;

	if (wifi_authdata == NULL) {
		DBG("the status error : no response yet");
		netconfig_error_fail_get_sim_auth_delay(&error);
		dbus_g_method_return_error(context, error);
		return FALSE;
	}

	switch (wifi_authdata->auth_result) {
	case TAPI_SIM_AUTH_NO_ERROR:
		 break;

	case TAPI_SIM_AUTH_SQN_FAILURE:
	case TAPI_SIM_AUTH_SYNCH_FAILURE:
		array = g_array_sized_new(FALSE, FALSE, sizeof(guchar), wifi_authdata->resp_length+1);
		res_len = (guchar)((wifi_authdata->resp_length-1) & 0xff);

		g_array_append_vals(array, &res_len, 1);
		g_array_append_vals(array, wifi_authdata->resp_data, wifi_authdata->resp_length);

		dbus_g_method_return(context, array);
		g_array_free (array, TRUE);

		g_free(wifi_authdata->resp_data);
		g_free(wifi_authdata);
		wifi_authdata = NULL;

		return TRUE;

	default:
		netconfig_error_fail_get_sim_auth_wrong_data(&error);
		dbus_g_method_return_error(context, error);
		__netconfig_tapi_deinit();
		return FALSE;
	}

	if ((wifi_authdata->resp_length >= AKA_AUTH_RES_MIN_LEN ||
			wifi_authdata->resp_length <= AKA_AUTH_RES_MAX_LEN) &&
			wifi_authdata->cipher_length == AKA_AUTH_CK_LEN &&
			wifi_authdata->integrity_length == AKA_AUTH_IK_LEN) {
		array = g_array_sized_new(FALSE, FALSE, sizeof(guchar), wifi_authdata->resp_length+AKA_AUTH_CK_LEN+AKA_AUTH_IK_LEN+1);

		res_len = (guchar)((wifi_authdata->resp_length-1) & 0xff);
		g_array_append_vals(array, &res_len, 1);
		g_array_append_vals(array, wifi_authdata->resp_data, wifi_authdata->resp_length);
		g_array_append_vals(array, wifi_authdata->cipher_data, AKA_AUTH_CK_LEN);
		g_array_append_vals(array, wifi_authdata->integrity_data, AKA_AUTH_IK_LEN);

		dbus_g_method_return(context, array);
		g_array_free (array, TRUE);
	} else {
		ERR("auth data length is wrong, res = [%d], Kc = [%d], Ki = [%d]",
				wifi_authdata->resp_length, wifi_authdata->cipher_length, wifi_authdata->integrity_length);

		netconfig_error_fail_get_sim_auth_wrong_data(&error);
		dbus_g_method_return_error(context, error);
		__netconfig_tapi_deinit();
		return FALSE;
	}

	__netconfig_tapi_deinit();
	return TRUE;
}

gboolean netconfig_iface_wifi_get_sim_imsi(NetconfigWifi *wifi, DBusGMethodInvocation *context)
{
	gboolean ret = TRUE;

	DBG("Get sim Imsi");

	g_return_val_if_fail(wifi != NULL, FALSE);

	ret = __netconfig_wifi_get_sim_imsi(context);

	return ret;
}

gboolean netconfig_iface_wifi_req_sim_auth(NetconfigWifi *wifi, GArray *rand_data, gboolean *result, GError **error)
{
	gboolean ret = TRUE;

	DBG("Req sim Authentication");

	g_return_val_if_fail(wifi != NULL, FALSE);

	ret = __netconfig_wifi_req_sim_auth(rand_data, error);

	*result = ret;
	return ret;
}

gboolean netconfig_iface_wifi_req_aka_auth(NetconfigWifi *wifi, GArray *rand_data, GArray *autn_data, gboolean *result, GError **error)
{
	gboolean ret = TRUE;

	DBG("Req aka Authentication");

	g_return_val_if_fail(wifi != NULL, FALSE);

	ret = __netconfig_wifi_req_aka_auth(rand_data, autn_data, error);

	*result = ret;
	return ret;
}

gboolean netconfig_iface_wifi_get_sim_auth(NetconfigWifi *wifi, DBusGMethodInvocation *context)
{
	gboolean ret = TRUE;

	DBG("Get sim Authdata");

	g_return_val_if_fail(wifi != NULL, FALSE);

	ret = __netconfig_wifi_get_sim_authdata(context);

	return ret;
}

gboolean netconfig_iface_wifi_get_aka_auth(NetconfigWifi *wifi, DBusGMethodInvocation *context)
{
	gboolean ret = TRUE;

	DBG("Get aka Authdata");

	g_return_val_if_fail(wifi != NULL, FALSE);

	ret = __netconfig_wifi_get_aka_authdata(context);

	return ret;
}
