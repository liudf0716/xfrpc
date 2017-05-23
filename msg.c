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

#include "msg.h"
#include "const.h"
#include "config.h"
#include "frame.h"

/*
const (
	TypeLogin         = 'o'
	TypeLoginResp     = '1'
	TypeNewProxy      = 'p'
	TypeNewProxyResp  = '2'
	TypeNewWorkConn   = 'w'
	TypeReqWorkConn   = 'r'
	TypeStartWorkConn = 's'
	TypePing          = 'h'
	TypePong          = '4'
	TypeUdpPacket     = 'u'
)
*/


/*
struct login {
	char		*version;
	char		*hostname;
	char 		*os;
	char		*arch;
	char 		*user;
	char 		*privilege_key;
	long int 	timestamp;
	char 		*run_id;
	int 		*pool_count;
};

	lg->version 		= strdup(PROTOCOL_VERESION);
	lg->hostname 		= NULL;
	lg->os 				= strdup(uname_buf.sysname);
	lg->arch 			= strdup(uname_buf.machine);
	lg->user 			= NULL;

	lg->timestamp 		= time(NULL);
	lg->run_id 			= NULL;
	lg->pool_count 		= 0;//TODO
	lg->privilege_key 	= NULL; //TODO
*/


#define JSON_MARSHAL_TYPE(jobj,key,jtype,item)		\
json_object_object_add(jobj, key, json_object_new_##jtype((item)));


int login_request_marshal(char **msg)
{
	int nret = 0;
	struct json_object *j_login_req = json_object_new_object();
	if (is_error(j_login_req))
		return 0;
	
	struct login *lg = get_common_login_config();
	if (!lg)
		return 0;
	
	JSON_MARSHAL_TYPE(j_login_req, "version", string, lg->version);
	JSON_MARSHAL_TYPE(j_login_req, "hostname", string, lg->hostname?lg->hostname:"\0");
	JSON_MARSHAL_TYPE(j_login_req, "os", string, lg->os);
	JSON_MARSHAL_TYPE(j_login_req, "arch", string, lg->arch);
	JSON_MARSHAL_TYPE(j_login_req, "user", string, lg->user?lg->user:"\0");
	JSON_MARSHAL_TYPE(j_login_req, "privilege_key", string, lg->privilege_key? lg->privilege_key:"\0");
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

int pack(struct message *msg, char **ret_buf)
{
	uint64_t  big_endian;
	size_t buf_len = TYPE_LEN + sizeof(big_endian) + msg->data_len + 1;
	big_endian = htobe64((uint64_t)msg->data_len);
	*ret_buf = calloc(buf_len, 1);

	if (*ret_buf == NULL) {
		return 0;
	}

	**ret_buf = msg->type;
	*(uint64_t *)(*ret_buf + 1) = big_endian;
	sprintf(*ret_buf + TYPE_LEN + sizeof(big_endian), msg->data_len + 1, "%s", msg->data_p);
	
	return buf_len;
}
