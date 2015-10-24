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

#include "log.h"
#include "util.h"
#include "netdbus.h"
#include "neterror.h"
#include "wifi-tel-intf.h"
#include "network-state.h"
#include "wifi-eap.h"

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

static struct wifii_authentication_data *wifi_authdata;

static void *__netconfig_wifi_free_wifi_authdata(
		struct wifii_authentication_data *data)
{
	if (data != NULL) {
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

static void __netconfig_wifi_clean_authentication(void)
{
	netconfig_tel_deinit();

	wifi_authdata = __netconfig_wifi_free_wifi_authdata(wifi_authdata);
}

static gboolean __netconfig_wifi_get_sim_imsi(Wifi *wifi,
		GDBusMethodInvocation *context)
{
	int ret;
	TapiHandle *handle;
	TelSimImsiInfo_t imsi_info;
	char *imsi;

	handle = (TapiHandle *)netconfig_tel_init();
	if (handle == NULL) {
		ERR("tapi_init failed");
		netconfig_error_fail_get_imsi(context);
		return FALSE;
	}

	ERR("before tel_get_sim_imsi");
	ret = tel_get_sim_imsi(handle, &imsi_info);
	ERR("after tel_get_sim_imsi");
	if (ret != TAPI_API_SUCCESS) {
		ERR("Failed tel_get_sim_imsi() : [%d]", ret);
		netconfig_error_fail_get_imsi(context);
		return FALSE;
	}

	imsi = g_strdup_printf("%s%s%s", imsi_info.szMcc,
			imsi_info.szMnc, imsi_info.szMsin);

	wifi_complete_get_sim_imsi(wifi, context, imsi);
	g_free(imsi);

	return TRUE;
}

void __netconfig_response_sim_authentication(TapiHandle *handle,
		int result, void *data, void *user_data)
{
	if (wifi_authdata != NULL)
		wifi_authdata = __netconfig_wifi_free_wifi_authdata(wifi_authdata);

	wifi_authdata = g_try_new0(struct wifii_authentication_data, 1);

	TelSimAuthenticationResponse_t *auth_resp =
				(TelSimAuthenticationResponse_t *) data;
	if (auth_resp == NULL) {
		ERR("the auth response is NULL");

		wifi_authdata->auth_result = -1;
		return;
	} else
		wifi_authdata->auth_result = auth_resp->auth_result;

	if (auth_resp->auth_result == TAPI_SIM_AUTH_NO_ERROR) {
		wifi_authdata->resp_length = auth_resp->resp_length;
		wifi_authdata->authentication_key_length =
					auth_resp->authentication_key_length;

		if (wifi_authdata->resp_data != NULL)
			g_free(wifi_authdata->resp_data);

		wifi_authdata->resp_data = g_strdup(auth_resp->resp_data);

		if (wifi_authdata->authentication_key != NULL)
			g_free(wifi_authdata->authentication_key);

		wifi_authdata->authentication_key =
							g_strdup(auth_resp->authentication_key);
	} else {
		ERR("the result error for sim auth : [%d]", auth_resp->auth_result);

		wifi_authdata->resp_length = 0;
		wifi_authdata->authentication_key_length = 0;
	}
}

void __netconfig_response_aka_authentication(TapiHandle *handle,
		int result, void *data, void *user_data)
{
	if (wifi_authdata != NULL)
		wifi_authdata = __netconfig_wifi_free_wifi_authdata(wifi_authdata);

	wifi_authdata = g_try_new0(struct wifii_authentication_data, 1);

	TelSimAuthenticationResponse_t *auth_resp =
					(TelSimAuthenticationResponse_t *) data;
	if (auth_resp == NULL) {
		ERR("the auth response is NULL");

		wifi_authdata->auth_result = -1;
		return;
	} else
		wifi_authdata->auth_result = auth_resp->auth_result;

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

static gboolean __netconfig_wifi_req_sim_auth(GArray *rand_data,
		GDBusMethodInvocation *context)
{
	int i;
	int ret;
	TapiHandle *handle;
	TelSimAuthenticationData_t auth_data;

	if (rand_data == NULL)
		return FALSE;

	if (rand_data->len != SIM_RAND_DATA_LEN) {
		ERR("wrong rand data len : [%d]", rand_data->len);

		netconfig_error_fail_req_sim_auth_wrong_param(context);
		return FALSE;
	}

	if ((ret = g_array_get_element_size(rand_data)) != 1) {
		ERR("wrong rand data size : [%d]", ret);

		netconfig_error_fail_req_sim_auth_wrong_param(context);
		return FALSE;
	}

	memset(&auth_data, 0, sizeof(auth_data));

	auth_data.auth_type = TAPI_SIM_AUTH_TYPE_GSM;
	auth_data.rand_length = SIM_RAND_DATA_LEN;

	for (i=0; i<rand_data->len; i++)
		auth_data.rand_data[i] = g_array_index(rand_data, guint8, i);

	handle = (TapiHandle *)netconfig_tel_init();
	if (handle == NULL) {
		netconfig_error_fail_req_sim_auth(context);
		return FALSE;
	}

	ret = tel_req_sim_authentication(handle,
			&auth_data, __netconfig_response_sim_authentication, NULL);
	if (ret != TAPI_API_SUCCESS) {
		ERR("Failed tel_req_sim_authentication() : [%d]", ret);

		netconfig_error_fail_req_sim_auth(context);
		return FALSE;
	}

	return TRUE;
}

static netconfig_error_e __netconfig_wifi_req_aka_auth(
		GArray *rand_data, GArray *autn_data, GDBusMethodInvocation *context)
{
	int i;
	int ret;
	TapiHandle *handle;
	TelSimAuthenticationData_t auth_data;

	if (rand_data == NULL || autn_data == NULL)
		return NETCONFIG_ERROR_FAILED_REQ_SIM_AUTH;

	if (rand_data->len != AKA_RAND_DATA_LEN) {
		ERR("wrong rand data len : [%d]", rand_data->len);

		return NETCONFIG_ERROR_FAILED_REQ_SIM_AUTH_WRONG_PARAM;
	}

	if (autn_data->len != AKA_AUTN_DATA_LEN) {
		ERR("wrong autn data len : [%d]", autn_data->len);

		return NETCONFIG_ERROR_FAILED_REQ_SIM_AUTH_WRONG_PARAM;
	}

	if ((ret = g_array_get_element_size(rand_data)) != 1) {
		ERR("wrong rand data size : [%d]", ret);

		return NETCONFIG_ERROR_FAILED_REQ_SIM_AUTH_WRONG_PARAM;
	}

	if ((ret = g_array_get_element_size(autn_data)) != 1) {
		ERR("wrong autn data size : [%d]", ret);

		return NETCONFIG_ERROR_FAILED_REQ_SIM_AUTH_WRONG_PARAM;
	}

	memset(&auth_data, 0, sizeof(auth_data));

	auth_data.auth_type = TAPI_SIM_AUTH_TYPE_3G;
	auth_data.rand_length = AKA_RAND_DATA_LEN;
	auth_data.autn_length = AKA_AUTN_DATA_LEN;

	for (i=0; i<rand_data->len; i++)
		auth_data.rand_data[i] = g_array_index(rand_data, guint8, i);

	for (i=0; i<autn_data->len; i++)
		auth_data.autn_data[i] = g_array_index(autn_data, guint8, i);

	handle = (TapiHandle *)netconfig_tel_init();
	if (handle == NULL) {
		return NETCONFIG_ERROR_FAILED_REQ_SIM_AUTH;
	}

	ret = tel_req_sim_authentication(handle, &auth_data,
			__netconfig_response_aka_authentication, NULL);

	if (ret != TAPI_API_SUCCESS) {
		ERR("Failed tel_req_sim_authentication() : [%d]", ret);

		return NETCONFIG_ERROR_FAILED_REQ_SIM_AUTH;
	}
	return NETCONFIG_NO_ERROR;
}

static gboolean __netconfig_wifi_get_sim_authdata(Wifi *wifi,
		GDBusMethodInvocation *context)
{
	GArray *array = NULL;

	if (wifi_authdata == NULL) {
		DBG("the status error : no response yet");
		netconfig_error_fail_get_sim_auth_delay(context);
		return FALSE;
	}

	if (wifi_authdata->auth_result == TAPI_SIM_AUTH_NO_ERROR) {
		if (wifi_authdata->resp_length == SIM_AUTH_SRES_LEN &&
				wifi_authdata->authentication_key_length == SIM_AUTH_KC_LEN) {
			array = g_array_sized_new(FALSE, FALSE, sizeof(guchar),
					SIM_AUTH_SRES_LEN+SIM_AUTH_KC_LEN);
			g_array_append_vals(array, wifi_authdata->resp_data,
					SIM_AUTH_SRES_LEN);
			g_array_append_vals(array, wifi_authdata->authentication_key,
					SIM_AUTH_KC_LEN);
		} else {
			ERR("auth data length is wrong, SRES = [%d], Kc = [%d]",
					wifi_authdata->resp_length,
					wifi_authdata->authentication_key_length);
			netconfig_error_fail_get_sim_auth_wrong_data(context);
			__netconfig_wifi_clean_authentication();
			return FALSE;
		}
	} else {
		ERR("failed auth result = [%d]", wifi_authdata->auth_result);
		netconfig_error_fail_get_sim_auth_wrong_data(context);
		__netconfig_wifi_clean_authentication();
		return FALSE;
	}

	wifi_complete_get_sim_auth(wifi, context, array->data);
	g_array_free (array, TRUE);
	__netconfig_wifi_clean_authentication();
	return TRUE;
}

static gboolean __netconfig_wifi_get_aka_authdata(Wifi *wifi, GDBusMethodInvocation *context)
{
	GArray *array = NULL;
	guchar res_len;

	if (wifi_authdata == NULL) {
		DBG("the status error : no response yet");
		netconfig_error_fail_get_sim_auth_delay(context);
		return FALSE;
	}

	switch (wifi_authdata->auth_result) {
	case TAPI_SIM_AUTH_NO_ERROR:
		 break;

	case TAPI_SIM_AUTH_SQN_FAILURE:
	case TAPI_SIM_AUTH_SYNCH_FAILURE:
		array = g_array_sized_new(FALSE, FALSE, sizeof(guchar),
									wifi_authdata->resp_length+1);
		res_len = (guchar)((wifi_authdata->resp_length-1) & 0xff);

		g_array_append_vals(array, &res_len, 1);
		g_array_append_vals(array, wifi_authdata->resp_data,
								wifi_authdata->resp_length);

		wifi_complete_get_aka_auth(wifi, context, array->data);
		g_array_free (array, TRUE);

		__netconfig_wifi_clean_authentication();

		return TRUE;

	default:
		netconfig_error_fail_get_sim_auth_wrong_data(context);
		__netconfig_wifi_clean_authentication();
		return FALSE;
	}

	if ((wifi_authdata->resp_length >= AKA_AUTH_RES_MIN_LEN ||
			wifi_authdata->resp_length <= AKA_AUTH_RES_MAX_LEN) &&
			wifi_authdata->cipher_length == AKA_AUTH_CK_LEN &&
			wifi_authdata->integrity_length == AKA_AUTH_IK_LEN) {
		array = g_array_sized_new(FALSE, FALSE, sizeof(guchar),
				wifi_authdata->resp_length+AKA_AUTH_CK_LEN+AKA_AUTH_IK_LEN+1);

		res_len = (guchar)((wifi_authdata->resp_length-1) & 0xff);
		g_array_append_vals(array, &res_len, 1);
		g_array_append_vals(array, wifi_authdata->resp_data,
								wifi_authdata->resp_length);
		g_array_append_vals(array, wifi_authdata->cipher_data,
								AKA_AUTH_CK_LEN);
		g_array_append_vals(array, wifi_authdata->integrity_data,
								AKA_AUTH_IK_LEN);
	} else {
		ERR("auth data length is wrong, res = [%d], Kc = [%d], Ki = [%d]",
				wifi_authdata->resp_length, wifi_authdata->cipher_length,
				wifi_authdata->integrity_length);

		netconfig_error_fail_get_sim_auth_wrong_data(context);
		__netconfig_wifi_clean_authentication();
		return FALSE;
	}

	wifi_complete_get_aka_auth(wifi, context, array->data);
	g_array_free (array, TRUE);
	__netconfig_wifi_clean_authentication();

	return TRUE;
}

gboolean handle_get_sim_imsi(Wifi *wifi, GDBusMethodInvocation *context)
{
	gboolean ret = TRUE;

	DBG("Get IMSI");

	g_return_val_if_fail(wifi != NULL, FALSE);

	ret = __netconfig_wifi_get_sim_imsi(wifi, context);

	return ret;
}

gboolean handle_req_sim_auth(Wifi *wifi, GDBusMethodInvocation *context, GVariant *rand_data)
{
	gboolean result = TRUE;
	GArray *rand_data_garray;
	GVariantIter *iter;
	gint length;
	guchar *out_auth_data;
	guchar byte;
	int i = 0;

	DBG("Request SIM Authentication");

	g_return_val_if_fail(wifi != NULL, FALSE);

	g_variant_get(rand_data, "ay", &iter);
	length = g_variant_iter_n_children(iter);
	out_auth_data = g_new0(guchar, length);

	while (g_variant_iter_loop(iter, "y", &byte)) {
		*(out_auth_data + i) = byte;
		i++;
	}
	g_variant_iter_free(iter);

	rand_data_garray = g_array_sized_new(FALSE, FALSE, sizeof(guchar), length);
	memcpy(rand_data_garray->data, out_auth_data, length);
	g_free(out_auth_data);
	rand_data_garray->len = length;

	result = __netconfig_wifi_req_sim_auth(rand_data_garray, context);
	g_array_free(rand_data_garray, FALSE);

	if (result) {
		wifi_complete_req_sim_auth(wifi, context, result);
	}

	return result;
}

gboolean handle_req_aka_auth(Wifi *wifi, GDBusMethodInvocation *context, GVariant *rand_data, GVariant *autn_data)
{
	netconfig_error_e ret = NETCONFIG_NO_ERROR;
	gboolean result = FALSE;
	GVariantIter *iter;
	gint length;
	guchar *out_auth_data;
	guchar byte;
	int i = 0;
	GArray *rand_data_garray;
	GArray *autn_data_garray;

	DBG("Request AKA Authentication");

	g_return_val_if_fail(wifi != NULL, FALSE);

	g_variant_get(rand_data, "ay", &iter);
	length = g_variant_iter_n_children(iter);
	out_auth_data = g_new0(guchar, length);
	while (g_variant_iter_loop(iter, "y", &byte)) {
		*(out_auth_data + i) = byte;
		i++;
	}
	g_variant_iter_free(iter);

	rand_data_garray = g_array_sized_new(FALSE, FALSE, sizeof(guchar), length);
	memcpy(rand_data_garray->data, out_auth_data, length);
	g_free(out_auth_data);
	rand_data_garray->len = length;

	i = 0;
	g_variant_get(autn_data, "ay", &iter);
	length = g_variant_iter_n_children(iter);
	out_auth_data = g_new0(guchar, length);
	while (g_variant_iter_loop(iter, "y", &byte)) {
		*(out_auth_data + i) = byte;
		i++;
	}
	g_variant_iter_free(iter);

	autn_data_garray = g_array_sized_new(FALSE, FALSE, sizeof(guchar), length);
	memcpy(autn_data_garray->data, out_auth_data, length);
	g_free(out_auth_data);
	autn_data_garray->len = length;

	ret = __netconfig_wifi_req_aka_auth(rand_data_garray, autn_data_garray, context);
	if (ret == NETCONFIG_NO_ERROR) {
		result = TRUE;
		wifi_complete_req_aka_auth(wifi, context, result);
	} else if (ret == NETCONFIG_ERROR_FAILED_REQ_SIM_AUTH_WRONG_PARAM) {
		netconfig_error_dbus_method_return(context,
				NETCONFIG_ERROR_FAILED_REQ_SIM_AUTH_WRONG_PARAM, "FailReqSimAuthWrongParam");
	} else {
		netconfig_error_dbus_method_return(context,
				NETCONFIG_ERROR_FAILED_REQ_SIM_AUTH, "FailReqSimAuth");
	}

	g_array_free(rand_data_garray, FALSE);
	g_array_free(autn_data_garray, FALSE);

	return result;
}

gboolean handle_get_sim_auth(Wifi *wifi, GDBusMethodInvocation *context)
{
	gboolean ret = TRUE;

	DBG("Get SIM Authdata");

	g_return_val_if_fail(wifi != NULL, FALSE);

	ret = __netconfig_wifi_get_sim_authdata(wifi, context);
	return ret;
}

gboolean handle_get_aka_auth(Wifi *wifi, GDBusMethodInvocation *context)
{
	gboolean ret = TRUE;

	DBG("Get AKA Authdata");

	g_return_val_if_fail(wifi != NULL, FALSE);

	ret = __netconfig_wifi_get_aka_authdata(wifi, context);

	return ret;
}
