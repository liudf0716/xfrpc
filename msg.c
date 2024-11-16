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
#include <openssl/evp.h>
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

#define JSON_MARSHAL_TYPE(jobj, key, jtype, item) \
	json_object_object_add(jobj, key, json_object_new_##jtype((item)));

#define SAFE_JSON_STRING(str_target) \
	str_target ? str_target : "\0"

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

static void 
calc_md5(const uint8_t *data, int datalen, uint8_t *digest) {
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) {
        debug(LOG_ERR, "Failed to create MD5 context");
        return;
    }

    if (EVP_DigestInit_ex(mdctx, EVP_md5(), NULL) != 1) {
        debug(LOG_ERR, "Failed to initialize MD5");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    if (EVP_DigestUpdate(mdctx, data, datalen) != 1) {
        debug(LOG_ERR, "Failed to update MD5");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    unsigned int md_len = 0;
    if (EVP_DigestFinal_ex(mdctx, digest, &md_len) != 1) {
        debug(LOG_ERR, "Failed to finalize MD5");
        EVP_MD_CTX_free(mdctx);
        return;
    }

    EVP_MD_CTX_free(mdctx);
}

static void
fill_custom_domains(struct json_object *j_ctl_req, const char *custom_domains)
{
	struct json_object *jarray_cdomains = json_object_new_array();
	assert(jarray_cdomains);
	char *tmp = strdup(custom_domains);
	assert(tmp);
	char *tok = tmp, *end = tmp;
	while (tok != NULL)
	{
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
new_work_conn()
{
	struct work_conn *work_c = calloc(1, sizeof(struct work_conn));
	assert(work_c);
	if (work_c)
		work_c->run_id = NULL;

	return work_c;
}

char *
get_auth_key(const char *token, long int *timestamp)
{
	*timestamp = time(NULL);
	char seed[128] = {0};
	snprintf(seed, 128, "%s%ld", token ? token : "", *timestamp);

	uint8_t digest[16] = {0};
	char *auth_key = (char *)malloc(33);
	assert(auth_key);
	calc_md5((const uint8_t *)seed, strlen(seed), digest);

	for (int i = 0; i < 16; i++)
		snprintf(auth_key + i * 2, 3, "%02x", digest[i]);

	auth_key[32] = '\0';
	return auth_key;
}

size_t
login_request_marshal(char **msg)
{
	size_t nret = 0;
	struct json_object *j_login_req = json_object_new_object();
	if (j_login_req == NULL)
		return 0;

	struct login *lg = get_common_login_config();
	if (!lg) {
		json_object_put(j_login_req);
		return 0;
	}

	SAFE_FREE(lg->privilege_key);
	struct common_conf *cf = get_common_config();
	char *auth_key = get_auth_key(cf->auth_token, &lg->timestamp);
	lg->privilege_key = strdup(auth_key);
	assert(lg->privilege_key);

	JSON_MARSHAL_TYPE(j_login_req, "version", string, lg->version);
	JSON_MARSHAL_TYPE(j_login_req, "hostname", string, SAFE_JSON_STRING(lg->hostname));
	JSON_MARSHAL_TYPE(j_login_req, "os", string, lg->os);
	JSON_MARSHAL_TYPE(j_login_req, "arch", string, lg->arch);
	if (lg->user)
		JSON_MARSHAL_TYPE(j_login_req, "user", string, SAFE_JSON_STRING(lg->user));

	JSON_MARSHAL_TYPE(j_login_req, "privilege_key", string, SAFE_JSON_STRING(lg->privilege_key));
	if (sizeof(time_t) == 4) {
		JSON_MARSHAL_TYPE(j_login_req, "timestamp", int, lg->timestamp);
	} else {
		JSON_MARSHAL_TYPE(j_login_req, "timestamp", int64, lg->timestamp);
	}
	if (lg->run_id)
		JSON_MARSHAL_TYPE(j_login_req, "run_id", string, SAFE_JSON_STRING(lg->run_id));
	JSON_MARSHAL_TYPE(j_login_req, "pool_count", int, lg->pool_count);
	//json_object_object_add(j_login_req, "metas", NULL);

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

int new_proxy_service_marshal(const struct proxy_service *np_req, char **msg)
{
	const char *tmp = NULL;
	int nret = 0;
	char *path = NULL;
	char *delimiter = ",";
	char *save = NULL;
	struct json_object *j_np_req = json_object_new_object();
	if (!j_np_req)
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

int new_work_conn_marshal(const struct work_conn *work_c, char **msg)
{
	const char *tmp = NULL;
	int nret = 0;
	struct json_object *j_new_work_conn = json_object_new_object();
	if (!j_new_work_conn)
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
	if (!json_object_object_get_ex(j_np_res, "remote_addr", &npr_proxy_remote_addr)) {
		free(npr->run_id);
		free(npr);
		npr = NULL;
		goto END_ERROR;
	}

	const char *remote_addr = json_object_get_string(npr_proxy_remote_addr);
	char *port = strrchr(remote_addr, ':');
	if (port) {
		port++;
		npr->remote_port = atoi(port);
	}

	struct json_object *npr_proxy_name = NULL;
	if (!json_object_object_get_ex(j_np_res, "proxy_name", &npr_proxy_name)) {
		free(npr->run_id);
		free(npr);
		npr = NULL;
		goto END_ERROR;
	}

	npr->proxy_name = strdup(json_object_get_string(npr_proxy_name));
	assert(npr->proxy_name);

	struct json_object *npr_error = NULL;
	if (json_object_object_get_ex(j_np_res, "error", &npr_error)) {
		npr->error = strdup(json_object_get_string(npr_error));
		assert(npr->error);
	}
	

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
	if (!json_object_object_get_ex(j_lg_res, "version", &l_version)) {
		free(lr);
		lr = NULL;
		goto END_ERROR;
	}

	lr->version = strdup(json_object_get_string(l_version));
	assert(lr->version);

	struct json_object *l_run_id = NULL;
	if (!json_object_object_get_ex(j_lg_res, "run_id", &l_run_id)) {
		free(lr->version);
		free(lr);
		lr = NULL;
		goto END_ERROR;
	}

	lr->run_id = strdup(json_object_get_string(l_run_id));
	assert(lr->run_id);

	struct json_object *l_error = NULL;
	if (json_object_object_get_ex(j_lg_res, "error", &l_error)) {
		lr->error = strdup(json_object_get_string(l_error));
		assert(lr->error);
	}

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
	if (!json_object_object_get_ex(j_start_w_res, "proxy_name", &pn)) {
		free(sr);
		sr = NULL;
		goto START_W_C_R_END;
	}

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
	if (!json_object_object_get_ex(j_ctl_res, "type", &jtype)) {
		free(ctl_res);
		ctl_res = NULL;
		goto END_ERROR;
	}
	ctl_res->type = json_object_get_int(jtype);

	struct json_object *jcode = NULL;
	if (!json_object_object_get_ex(j_ctl_res, "code", &jcode)) {
		free(ctl_res);
		ctl_res = NULL;
		goto END_ERROR;
	}

	ctl_res->code = json_object_get_int(jcode);

	struct json_object *jmsg = NULL;
	if (!json_object_object_get_ex(j_ctl_res, "msg", &jmsg)) {
		free(ctl_res);
		ctl_res = NULL;
		goto END_ERROR;
	}
	ctl_res->msg = strdup(json_object_get_string(jmsg));
	assert(ctl_res->msg);

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

/**
 * Creates a JSON object representation of a UDP address structure.
 *
 * @param addr Pointer to the UDP address structure to be converted to JSON
 * @return struct json_object* A pointer to the created JSON object representing the UDP address,
 *                            or NULL if creation fails
 */
static struct json_object *create_udp_addr_json(const struct udp_addr *addr) {
	if (!addr) {
		struct json_object *empty = json_object_new_object();
		assert(empty);
		return empty;
	}

	struct json_object *j_addr = json_object_new_object();
	if (!j_addr) return NULL;

	// Add IP
	struct json_object *j_ip = json_object_new_string(addr->addr);
	assert(j_ip);
	json_object_object_add(j_addr, "IP", j_ip);

	// Add Port
	struct json_object *j_port = json_object_new_int(addr->port);
	assert(j_port);
	json_object_object_add(j_addr, "Port", j_port);

	// Add Zone (empty string if not specified)
	struct json_object *j_zone = json_object_new_string("");
	assert(j_zone);
	json_object_object_add(j_addr, "Zone", j_zone);

	return j_addr;
}

/**
 * Marshals a UDP packet structure into a serialized message format.
 *
 * @param udp  Pointer to the UDP packet structure to be marshalled
 * @param msg  Pointer to a char pointer that will store the serialized message.
 *             The caller is responsible for freeing this memory.
 * 
 * @return     Returns 0 on success, negative value on error
 */
int new_udp_packet_marshal(const struct udp_packet *udp, char **msg) {
	if (!udp || !msg) return -1;

	// Create main JSON object
	struct json_object *j_udp = json_object_new_object();
	if (!j_udp) return -1;

	// Add content
	if (udp->content) {
		struct json_object *content = json_object_new_string(udp->content);
		assert(content);
		json_object_object_add(j_udp, "c", content);
	}

	// Add local address
	struct json_object *j_laddr = create_udp_addr_json(udp->laddr);
	assert(j_laddr);
	json_object_object_add(j_udp, "l", j_laddr);

	// Add remote address
	struct json_object *j_raddr = create_udp_addr_json(udp->raddr);
	assert(j_raddr);
	json_object_object_add(j_udp, "r", j_raddr);

	// Convert to string
	const char *json_str = json_object_to_json_string(j_udp);
	if (!json_str) {
		json_object_put(j_udp);
		return -1;
	}

	*msg = strdup(json_str);
	assert(*msg);

	json_object_put(j_udp);
	return 0;
}

/**
 * @brief Frees memory allocated for a UDP packet structure and its components
 *
 * This function safely deallocates memory for a UDP packet structure including:
 * - Packet content
 * - Local address structure (addr and zone)
 * - Remote address structure (addr and zone)
 * - The UDP packet structure itself
 *
 * @param udp Pointer to the UDP packet structure to be freed
 * @note Function checks for NULL pointers before attempting to free memory
 */
void udp_packet_free(struct udp_packet *udp)
{
	if (!udp)
		return;

	SAFE_FREE(udp->content);

	if (udp->laddr) {
		SAFE_FREE(udp->laddr->addr);
		SAFE_FREE(udp->laddr->zone);
		SAFE_FREE(udp->laddr);
	}

	if (udp->raddr) {
		SAFE_FREE(udp->raddr->addr);
		SAFE_FREE(udp->raddr->zone); 
		SAFE_FREE(udp->raddr);
	}

	SAFE_FREE(udp);
}


/**
 * @brief Parses a JSON object to create a UDP address structure
 * 
 * @param j_addr JSON object containing UDP address information
 * @return struct udp_addr* Pointer to newly allocated UDP address structure,
 *         or NULL if parsing fails or memory allocation fails
 *
 * @note The caller is responsible for freeing the returned structure
 */
static struct udp_addr *parse_udp_addr(struct json_object *j_addr) {
	if (!j_addr) return NULL;

	struct json_object *j_ip = NULL, *j_port = NULL, *j_zone = NULL;
	if (!json_object_object_get_ex(j_addr, "IP", &j_ip) ||
		!json_object_object_get_ex(j_addr, "Port", &j_port) ||
		!json_object_object_get_ex(j_addr, "Zone", &j_zone)) {
		return NULL;
	}

	struct udp_addr *addr = calloc(1, sizeof(struct udp_addr));
	if (!addr) return NULL;

	addr->addr = strdup(json_object_get_string(j_ip));
	addr->zone = strdup(json_object_get_string(j_zone));
	addr->port = json_object_get_int(j_port);

	if (!addr->addr || !addr->zone) {
		SAFE_FREE(addr->addr);
		SAFE_FREE(addr->zone);
		SAFE_FREE(addr);
		return NULL;
	}

	return addr;
}

/**
 * Unmarshal a UDP packet from a string message.
 * 
 * @param msg     The string message containing the UDP packet data to unmarshal.
 * @return        Pointer to the unmarshaled UDP packet structure, or NULL if error occurs.
 */
struct udp_packet *udp_packet_unmarshal(const char *msg) {
	if (!msg) return NULL;

	struct json_object *j_udp = json_tokener_parse(msg);
	if (!j_udp) return NULL;

	struct udp_packet *udp = calloc(1, sizeof(struct udp_packet));
	if (!udp) {
		json_object_put(j_udp);
		return NULL;
	}

	// Parse content
	struct json_object *j_content = NULL;
	if (!json_object_object_get_ex(j_udp, "c", &j_content)) {
		goto error;
	}
	udp->content = strdup(json_object_get_string(j_content));
	if (!udp->content) goto error;

	// Parse local address
	struct json_object *j_laddr = NULL;
	if (!json_object_object_get_ex(j_udp, "l", &j_laddr)) {
		goto error;
	}
	udp->laddr = parse_udp_addr(j_laddr);
	if (!udp->laddr) goto error;

	// Parse remote address
	struct json_object *j_raddr = NULL;
	if (!json_object_object_get_ex(j_udp, "r", &j_raddr)) {
		goto error;
	}
	udp->raddr = parse_udp_addr(j_raddr);
	if (!udp->raddr) goto error;

	json_object_put(j_udp);
	return udp;

error:
	json_object_put(j_udp);
	udp_packet_free(udp);
	return NULL;
}
