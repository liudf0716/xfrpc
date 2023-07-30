/* vim: set et ts=4 sts=4 sw=4 : */
/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
\********************************************************************/

/** @file msg.c
    @brief xfrpc client msg related
    @author Copyright (C) 2016 Dengfeng Liu <liu_df@qq.com>
*/

#include <string.h>
#include <stdio.h>
#include <json-c/json.h>
#include <openssl/md5.h>
#include <time.h>
#include <assert.h>
#include <syslog.h>
#include <netinet/in.h>

#include "msg.h"
#include "config.h"
#include "debug.h"
#include "common.h"
#include "login.h"
#include "client.h"
#include "utils.h"

#define JSON_MARSHAL_TYPE(jobj,key,jtype,item)		\
json_object_object_add(jobj, key, json_object_new_##jtype((item)));

#define SAFE_JSON_STRING(str_target) \
str_target?str_target:"\0"

const char msg_types[] = {TypeLogin, 
						 TypeLoginResp, 
						 TypeNewProxy, 
						 TypeNewProxyResp, 
						 TypeNewWorkConn, 
						 TypeReqWorkConn, 
						 TypeStartWorkConn, 
						 TypePing, 
						 TypePong, 
						 TypeUDPPacket};

char *
calc_md5(const char *data, int datalen)
{
	unsigned char digest[16] = {0};
	char *out = (char*)malloc(33);
	assert(out);

	MD5_CTX md5;
	
	MD5_Init(&md5);
	MD5_Update(&md5, data, datalen);
	MD5_Final(digest, &md5);
	
	for (int n = 0; n < 16; ++n) {
        snprintf(&(out[n*2]), 3, "%02x", (unsigned int)digest[n]);
    }

    return out;
}

static void 
fill_custom_domains(struct json_object *j_ctl_req, const char *custom_domains)
{
	struct json_object *jarray_cdomains = json_object_new_array();
	assert(jarray_cdomains);
	char *tmp = strdup(custom_domains);
	assert(tmp);
	char *tok = tmp, *end = tmp;
	while (tok != NULL) {
		strsep(&end, ",");

		int dname_len = strlen(tok) + 1;
		char *dname_buf = (char *)calloc(1, dname_len);
		assert(dname_buf);
		dns_unified(tok, dname_buf, dname_len);
		json_object_array_add(jarray_cdomains, json_object_new_string(dname_buf));

		free(dname_buf);
		tok = end;
	}
	SAFE_FREE(tmp);
	
	json_object_object_add(j_ctl_req, "custom_domains", jarray_cdomains);
}

struct work_conn *
new_work_conn() {
	struct work_conn *work_c = calloc(1, sizeof(struct work_conn));
	assert(work_c);
	if (work_c) 
		work_c->run_id = NULL;

	return work_c;
}

char *
get_auth_key(const char *token, long int *timestamp)
{
	char seed[128] = {0};
	*timestamp = time(NULL);
	if (token)
		snprintf(seed, 128, "%s%ld", token, *timestamp);
	else
		snprintf(seed, 128, "%ld", *timestamp);
	
	return calc_md5(seed, strlen(seed));
}

size_t 
login_request_marshal(char **msg)
{
	size_t nret = 0;
	struct json_object *j_login_req = json_object_new_object();
	if (j_login_req == NULL)
		return 0;
	
	struct login *lg = get_common_login_config();
	if (!lg)
		return 0;
	
	SAFE_FREE(lg->privilege_key);
	struct common_conf *cf = get_common_config();
	char *auth_key = get_auth_key(cf->auth_token, &lg->timestamp);
	lg->privilege_key = strdup(auth_key);
	assert(lg->privilege_key);
	
	JSON_MARSHAL_TYPE(j_login_req, "version", string, lg->version);
	JSON_MARSHAL_TYPE(j_login_req, "hostname", string, SAFE_JSON_STRING(lg->hostname));
	JSON_MARSHAL_TYPE(j_login_req, "os", string, lg->os);
	JSON_MARSHAL_TYPE(j_login_req, "arch", string, lg->arch);
	JSON_MARSHAL_TYPE(j_login_req, "user", string, SAFE_JSON_STRING(lg->user));

	JSON_MARSHAL_TYPE(j_login_req, "privilege_key", string, SAFE_JSON_STRING(lg->privilege_key));
	JSON_MARSHAL_TYPE(j_login_req, "timestamp", int64, lg->timestamp);
	JSON_MARSHAL_TYPE(j_login_req, "run_id", string, SAFE_JSON_STRING(lg->run_id));
	JSON_MARSHAL_TYPE(j_login_req, "pool_count", int, lg->pool_count);
	json_object_object_add(j_login_req, "metas", NULL);
	
	const char *tmp = NULL;
	tmp = json_object_to_json_string(j_login_req);
	if (tmp && strlen(tmp) > 0) {
		nret = strlen(tmp);
		*msg = strdup(tmp);
		assert(*msg);
	}
	json_object_put(j_login_req);
	SAFE_FREE(auth_key);
	return nret;
}

int 
new_proxy_service_marshal(const struct proxy_service *np_req, char **msg)
{
	const char *tmp = NULL;
	int  nret = 0;
	char *path = NULL;
	char *delimiter = ",";
	char *save = NULL;
	struct json_object *j_np_req = json_object_new_object();
	if ( ! j_np_req)
		return 0;
	
	JSON_MARSHAL_TYPE(j_np_req, "proxy_name", string, np_req->proxy_name);
	// if proxy_type is socks5, set the proxy_type to tcp
	if (strcmp(np_req->proxy_type, "socks5") == 0 || strcmp(np_req->proxy_type, "mstsc") == 0) {
		JSON_MARSHAL_TYPE(j_np_req, "proxy_type", string, "tcp");
	} else {
		JSON_MARSHAL_TYPE(j_np_req, "proxy_type", string, np_req->proxy_type);
	}
	JSON_MARSHAL_TYPE(j_np_req, "use_encryption", boolean, np_req->use_encryption);
	JSON_MARSHAL_TYPE(j_np_req, "use_compression", boolean, np_req->use_compression);

	// if proxy_type is tcp, http, https and socks5, set group and group_key to j_np_req
	if (strcmp(np_req->proxy_type, "tcp") == 0 || 
		strcmp(np_req->proxy_type, "http") == 0 || 
		strcmp(np_req->proxy_type, "https") == 0 || 
		strcmp(np_req->proxy_type, "socks5") == 0) {
		
		if (np_req->group) {
			JSON_MARSHAL_TYPE(j_np_req, "group", string, np_req->group);
		}
		if (np_req->group_key) {
			JSON_MARSHAL_TYPE(j_np_req, "group_key", string, np_req->group_key);
		}
	}

	if (is_ftp_proxy(np_req)) {
		JSON_MARSHAL_TYPE(j_np_req, "remote_data_port", int, np_req->remote_data_port);
	}

	if (np_req->custom_domains) {
		fill_custom_domains(j_np_req, np_req->custom_domains);
		json_object_object_add(j_np_req, "remote_port", NULL);
	} else {
		json_object_object_add(j_np_req, "custom_domains", NULL);
		if (np_req->remote_port != -1) {
			JSON_MARSHAL_TYPE(j_np_req, "remote_port", int, np_req->remote_port);
		} else {
			json_object_object_add(j_np_req, "remote_port", NULL);
		}
	}

	JSON_MARSHAL_TYPE(j_np_req, "subdomain", string, SAFE_JSON_STRING(np_req->subdomain));

	json_object *j_location_array = json_object_new_array();
	if (np_req->locations) {
		json_object_object_add(j_np_req, "locations", j_location_array);
		path = strtok_r(np_req->locations, delimiter, &save);
		while (path) {
			json_object_array_add(j_location_array, json_object_new_string(path));
			path = strtok_r(NULL, delimiter, &save);
		}
	} else {
		json_object_object_add(j_np_req, "locations", NULL);
	}
	
	JSON_MARSHAL_TYPE(j_np_req, "host_header_rewrite", string, SAFE_JSON_STRING(np_req->host_header_rewrite));
	JSON_MARSHAL_TYPE(j_np_req, "http_user", string, SAFE_JSON_STRING(np_req->http_user));
	JSON_MARSHAL_TYPE(j_np_req, "http_pwd", string, SAFE_JSON_STRING(np_req->http_pwd));
		
	tmp = json_object_to_json_string(j_np_req);
	if (tmp && strlen(tmp) > 0) {
		nret = strlen(tmp);
		*msg = strdup(tmp);
		assert(*msg);
	}
	json_object_put(j_np_req);

	return nret;
}

int 
new_work_conn_marshal(const struct work_conn *work_c, char **msg)
{
	const char *tmp = NULL;
	int nret = 0;
	struct json_object *j_new_work_conn = json_object_new_object();
	if (! j_new_work_conn)
		return 0;

	JSON_MARSHAL_TYPE(j_new_work_conn, "run_id", string, SAFE_JSON_STRING(work_c->run_id));
	tmp = json_object_to_json_string(j_new_work_conn);
	if (tmp && strlen(tmp) > 0) {
		nret = strlen(tmp);
		*msg = strdup(tmp);
		assert(*msg);
	}

	json_object_put(j_new_work_conn);

	return nret;
}

// result returned of this func need be free
struct new_proxy_response *
new_proxy_resp_unmarshal(const char *jres)
{
	struct json_object *j_np_res = json_tokener_parse(jres);
	if (j_np_res == NULL)
		return NULL;
	
	struct new_proxy_response *npr = calloc(1, sizeof(struct new_proxy_response));
	assert(npr);

	struct json_object *npr_run_id = NULL;
	if (json_object_object_get_ex(j_np_res, "run_id", &npr_run_id))
		npr->run_id = strdup(json_object_get_string(npr_run_id));

	struct json_object *npr_proxy_remote_addr = NULL;
	if (! json_object_object_get_ex(j_np_res, "remote_addr", &npr_proxy_remote_addr))
		goto END_ERROR;
	const char *remote_addr = json_object_get_string(npr_proxy_remote_addr);
	char *port = strrchr(remote_addr, ':');
	if (port) {
		port++;
		npr->remote_port = atoi(port);
	}

	struct json_object *npr_proxy_name = NULL;
	if (! json_object_object_get_ex(j_np_res, "proxy_name", &npr_proxy_name))
		goto END_ERROR;
	npr->proxy_name = strdup(json_object_get_string(npr_proxy_name));
	assert(npr->proxy_name);

	struct json_object *npr_error = NULL;
	if(! json_object_object_get_ex(j_np_res, "error", &npr_error))
		goto END_ERROR;
	npr->error = strdup(json_object_get_string(npr_error));
	assert(npr->error);

END_ERROR:
	json_object_put(j_np_res);
	return npr;
}

// login_resp_unmarshal NEED FREE
struct login_resp *
login_resp_unmarshal(const char *jres)
{
	struct json_object *j_lg_res = json_tokener_parse(jres);
	if (j_lg_res == NULL)
		return NULL;
	
	struct login_resp *lr = calloc(1, sizeof(struct login_resp));
	assert(lr);

	struct json_object *l_version = NULL;
	if (! json_object_object_get_ex(j_lg_res, "version", &l_version))
		goto END_ERROR;
	lr->version = strdup(json_object_get_string(l_version));
	assert(lr->version);

	struct json_object *l_run_id = NULL;
	if (! json_object_object_get_ex(j_lg_res, "run_id", &l_run_id))
		goto END_ERROR;
	lr->run_id = strdup(json_object_get_string(l_run_id));
	assert(lr->run_id);

	struct json_object *l_error = NULL;
	if(! json_object_object_get_ex(j_lg_res, "error", &l_error))
		goto END_ERROR;
	lr->error = strdup(json_object_get_string(l_error));
	assert(lr->error);

END_ERROR:
	json_object_put(j_lg_res);
	return lr;
}

struct start_work_conn_resp *
start_work_conn_resp_unmarshal(const char *resp_msg)
{
	struct json_object *j_start_w_res = json_tokener_parse(resp_msg);
	if (j_start_w_res == NULL)
		return NULL;

	struct start_work_conn_resp *sr = calloc(1, sizeof(struct start_work_conn_resp));
	assert(sr);

	struct json_object *pn = NULL;
	if(! json_object_object_get_ex(j_start_w_res, "proxy_name", &pn))
		goto START_W_C_R_END;

	sr->proxy_name = strdup(json_object_get_string(pn));
	assert(sr->proxy_name);

START_W_C_R_END:
	json_object_put(j_start_w_res);
	return sr;
}

struct control_response *
control_response_unmarshal(const char *jres)
{
	struct json_object *j_ctl_res = json_tokener_parse(jres);
	if (j_ctl_res == NULL)
		return NULL;
	struct control_response *ctl_res = calloc(sizeof(struct control_response), 1);
	assert(ctl_res);
	
	struct json_object *jtype = NULL;
	if(! json_object_object_get_ex(j_ctl_res, "type", &jtype))
		goto END_ERROR;
	ctl_res->type = json_object_get_int(jtype);
	
	struct json_object *jcode = NULL;
	if(! json_object_object_get_ex(j_ctl_res, "code", &jcode))
		goto END_ERROR;
	ctl_res->code = json_object_get_int(jcode);
	
	struct json_object *jmsg = NULL;
	if(json_object_object_get_ex(j_ctl_res, "msg", &jmsg)) {
		ctl_res->msg = strdup(json_object_get_string(jmsg));
		assert(ctl_res->msg);
	}

END_ERROR:
	json_object_put(j_ctl_res);
	return ctl_res;
}

void 
control_response_free(struct control_response *res)
{
	if (!res)
		return;
	
	SAFE_FREE(res->msg);
	SAFE_FREE(res);
}

int 
msg_type_valid_check(char msg_type)
{
	int i = 0;
	for(i = 0; i<(sizeof(msg_types) / sizeof(*msg_types)); i++) {
		if (msg_types[i] == msg_type)
			return 1;
	}

	return 0;
}

char *
get_msg_type(uint8_t type) 
{
	return NULL;
}

