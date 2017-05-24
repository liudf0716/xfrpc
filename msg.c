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
    @brief xfrp client msg related
    @author Copyright (C) 2016 Dengfeng Liu <liudengfeng@kunteng.org>
*/

#include <string.h>
#include <stdio.h>
#include <json-c/json.h>
#include <json-c/bits.h>
#include <stdint.h>
#include <inttypes.h>
#include <openssl/md5.h>
#include <time.h>
#include <assert.h>

#include "msg.h"
#include "const.h"
#include "config.h"
#include "frame.h"

#define MSG_TYPE_I 	0
#define MSG_LEN_I 	1
#define MSG_DATA_I	9


uint64_t
ntoh64(const uint64_t *input)
{
    uint64_t rval;
    uint8_t *data = (uint8_t *)&rval;

    data[0] = *input >> 56;
    data[1] = *input >> 48;
    data[2] = *input >> 40;
    data[3] = *input >> 32;
    data[4] = *input >> 24;
    data[5] = *input >> 16;
    data[6] = *input >> 8;
    data[7] = *input >> 0;

    return rval;
}

uint64_t
hton64(const uint64_t *input)
{
    return (ntoh64(input));
}

#define JSON_MARSHAL_TYPE(jobj,key,jtype,item)		\
json_object_object_add(jobj, key, json_object_new_##jtype((item)));


static char *calc_md5(const char *data, int datalen)
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

char *get_auth_key(const char *token)
{
	char seed[128] = {0};
	snprintf(seed, 128, "%s%ld", token, time(NULL));
	
	return calc_md5(seed, strlen(seed));
}

size_t login_request_marshal(char **msg)
{
	size_t nret = 0;
	struct json_object *j_login_req = json_object_new_object();
	if (is_error(j_login_req))
		return 0;
	
	struct login *lg = get_common_login_config();
	if (!lg)
		return 0;
	
	struct common_conf *cf = get_common_config();
	char *auth_key = get_auth_key(cf->privilege_token);
	
	JSON_MARSHAL_TYPE(j_login_req, "version", string, lg->version);
	JSON_MARSHAL_TYPE(j_login_req, "hostname", string, lg->hostname?lg->hostname:"\0");
	JSON_MARSHAL_TYPE(j_login_req, "os", string, lg->os);
	JSON_MARSHAL_TYPE(j_login_req, "arch", string, lg->arch);
	JSON_MARSHAL_TYPE(j_login_req, "user", string, lg->user?lg->user:"\0");

	JSON_MARSHAL_TYPE(j_login_req, "privilege_key", string, lg->privilege_key? lg->privilege_key:auth_key);
	JSON_MARSHAL_TYPE(j_login_req, "timestamp", int64, lg->timestamp);
	JSON_MARSHAL_TYPE(j_login_req, "run_id", string, lg->run_id?lg->run_id:"\0");
	JSON_MARSHAL_TYPE(j_login_req, "pool_count", int, lg->pool_count);

	const char *tmp = NULL;
	tmp = json_object_to_json_string(j_login_req);
	if (tmp && strlen(tmp) > 0) {
		nret = strlen(tmp);
		*msg = strdup(tmp);
	}
	json_object_put(j_login_req);
	free(auth_key);
	return nret;
}

int control_request_marshal(const struct control_request *req, char **msg)
{
	const char *tmp = NULL;
	int  nret = 0;
	struct json_object *j_ctl_req = json_object_new_object();
	if (!j_ctl_req)
		return 0;
	
	json_object_object_add(j_ctl_req, "type", json_object_new_int(req->type));
	json_object_object_add(j_ctl_req, "proxy_name", json_object_new_string(req->proxy_name));
	json_object_object_add(j_ctl_req, "auth_key", 
						   json_object_new_string(req->auth_key?req->auth_key:""));
	if (req->type == TypeLogin)
		goto END_PROCESS; //TODO
	json_object_object_add(j_ctl_req, "use_encryption", json_object_new_boolean(req->use_encryption));
	json_object_object_add(j_ctl_req, "use_gzip", json_object_new_boolean(req->use_gzip));
	json_object_object_add(j_ctl_req, "pool_count", json_object_new_int(req->pool_count));
	json_object_object_add(j_ctl_req, "privilege_mode", json_object_new_boolean(req->privilege_mode));
	json_object_object_add(j_ctl_req, "privilege_key", 
						   json_object_new_string(req->privilege_key?req->privilege_key:""));
	json_object_object_add(j_ctl_req, "proxy_type", 
						   json_object_new_string(req->proxy_type?req->proxy_type:""));
	json_object_object_add(j_ctl_req, "remote_port", json_object_new_int(req->remote_port));
	if (!req->custom_domains)
		json_object_object_add(j_ctl_req, "custom_domains", NULL);
	else {
		// need to implement it
		;
	}
	if (!req->locations)
		json_object_object_add(j_ctl_req, "locations", NULL);
	else {
		// need to implement it
		;
	}
		
	json_object_object_add(j_ctl_req, "host_header_rewrite", 
						   json_object_new_string(req->host_header_rewrite?req->host_header_rewrite:""));
	json_object_object_add(j_ctl_req, "http_username", 
						   json_object_new_string(req->http_username?req->http_username:""));
	json_object_object_add(j_ctl_req, "http_password", 
						   json_object_new_string(req->http_password?req->http_password:""));
	json_object_object_add(j_ctl_req, "subdomain", 
						   json_object_new_string(req->subdomain?req->subdomain:""));
	json_object_object_add(j_ctl_req, "timestamp", json_object_new_int(req->timestamp));
	
END_PROCESS:
	tmp = json_object_to_json_string(j_ctl_req);
	if (tmp && strlen(tmp) > 0) {
		nret = strlen(tmp);
		*msg = strdup(tmp);
	}
	json_object_put(j_ctl_req);
	return nret;
}

struct control_response *control_response_unmarshal(const char *jres)
{
	struct json_object *j_ctl_res = json_tokener_parse(jres);
	if (is_error(j_ctl_res))
		return NULL;
	struct control_response *ctl_res = calloc(sizeof(struct control_response), 1);
	if (ctl_res == NULL) {
		goto END_ERROR;
	}
	
	struct json_object *jtype = json_object_object_get(j_ctl_res, "type");
	if (jtype == NULL) {
		goto END_ERROR;
	}
	ctl_res->type = json_object_get_int(jtype);
	
	struct json_object *jcode = json_object_object_get(j_ctl_res, "code");
	if (jcode == NULL)
		goto END_ERROR;
	ctl_res->code = json_object_get_int(jcode);
	
	struct json_object *jmsg = json_object_object_get(j_ctl_res, "msg");
	if (jmsg)
		ctl_res->msg = strdup(json_object_get_string(jmsg));
	
END_ERROR:
	json_object_put(j_ctl_res);
	return ctl_res;
}

void control_response_free(struct control_response *res)
{
	if (!res)
		return;
	
	if (res->msg) free(res->msg);
	
	free(res);
}

struct message *unpack(char *recv_msg, const ushort len)
{
	struct message *msg = calloc(sizeof(struct message), 1); //TODO: FREE
	if ( ! msg) 
		return NULL;

	msg->type = *(recv_msg + MSG_TYPE_I);

	uint64_t  data_len_bigend;
	data_len_bigend = *(uint64_t *)(recv_msg + MSG_LEN_I);
	msg->data_len = ntoh64(&data_len_bigend);
	msg->data_p = calloc(msg->data_len + 1, 1);
	if (! msg->data_p)
		return NULL;
	
	memcpy(msg->data_p, recv_msg + MSG_DATA_I, msg->data_len);
	return msg;
}

size_t pack(struct message *req_msg, char **ret_buf)
{
	uint64_t  data_len_bigend;
	size_t buf_len = TYPE_LEN + sizeof(data_len_bigend) + req_msg->data_len + 1;

	int endian_check = 1;
	// little endian if true
	if(*(char *)&endian_check == 1) 
	{
		printf("is little endian ! msg->data_len = %ld\n", req_msg->data_len);
		data_len_bigend = hton64(&req_msg->data_len);
	} else {
		data_len_bigend = req_msg->data_len;
	}


	printf("big endian = %lu\ttest=%lu\n", data_len_bigend, test);
	*ret_buf = calloc(buf_len, 1);

	if (*ret_buf == NULL) {
		return 0;
	}

	*(*ret_buf + MSG_TYPE_I) = req_msg->type;
	*(uint64_t *)(*ret_buf + MSG_LEN_I) = data_len_bigend;
	snprintf(*ret_buf + TYPE_LEN + sizeof(data_len_bigend), 
				req_msg->data_len + 1, 
				"%s", 
				req_msg->data_p);

	return buf_len;
}
