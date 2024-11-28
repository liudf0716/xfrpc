
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
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

/**
 * @brief Macro to add a typed value to a JSON object
 * @param jobj JSON object to add to
 * @param key Key name 
 * @param jtype JSON type (string, int, boolean, etc)
 * @param item Value to add
 */
#define JSON_MARSHAL_TYPE(jobj, key, jtype, item) \
	json_object_object_add(jobj, key, json_object_new_##jtype((item)))

/**
 * @brief Macro to safely handle NULL strings in JSON
 * @param str_target String to check
 * @return Original string if not NULL, empty string if NULL
 */
#define SAFE_JSON_STRING(str_target) \
	((str_target) ? (str_target) : "\0")

/**
 * @brief Calculate MD5 hash of input data
 *
 * @param data Input data buffer to hash
 * @param datalen Length of input data in bytes
 * @param digest Output buffer for MD5 hash (must be at least 16 bytes)
 * @return int 0 on success, -1 on failure
 * 
 * @note This function uses OpenSSL's EVP interface to calculate MD5 hash.
 *       The digest parameter must point to a buffer of at least 16 bytes.
 */
static int calc_md5(const uint8_t *data, int datalen, uint8_t *digest)
{
	if (!data || !digest || datalen <= 0) {
		debug(LOG_ERR, "Invalid parameters for MD5 calculation");
		return -1;
	}

	EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
	if (!mdctx) {
		debug(LOG_ERR, "Failed to create MD5 context");
		return -1;
	}

	int ret = -1;
	const EVP_MD *md = EVP_md5();
	if (!md) {
		debug(LOG_ERR, "Failed to get MD5 algorithm");
		goto cleanup;
	}

	if (EVP_DigestInit_ex(mdctx, md, NULL) != 1) {
		debug(LOG_ERR, "Failed to initialize MD5");
		goto cleanup;
	}

	if (EVP_DigestUpdate(mdctx, data, datalen) != 1) {
		debug(LOG_ERR, "Failed to update MD5");
		goto cleanup;
	}

	unsigned int md_len = 0;
	if (EVP_DigestFinal_ex(mdctx, digest, &md_len) != 1) {
		debug(LOG_ERR, "Failed to finalize MD5");
		goto cleanup;
	}

	ret = 0; // Success

cleanup:
	EVP_MD_CTX_free(mdctx);
	return ret;
}

/**
 * @brief Fills a JSON object with an array of custom domain names
 *
 * @param j_ctl_req JSON object to add custom domains array to
 * @param custom_domains Comma-separated string of domain names
 * @return void
 */
static void fill_custom_domains(struct json_object *j_ctl_req, const char *custom_domains) 
{
	if (!j_ctl_req || !custom_domains) {
		return;
	}

	struct json_object *domain_array = json_object_new_array();
	if (!domain_array) {
		return;
	}

	char *domains_copy = strdup(custom_domains);
	if (!domains_copy) {
		json_object_put(domain_array);
		return;
	}

	// Parse comma-separated domains
	char *saveptr = NULL;
	char *domain = strtok_r(domains_copy, ",", &saveptr);
	
	while (domain) {
		// Allocate buffer for normalized domain
		size_t domain_len = strlen(domain) + 1;
		char *normalized = calloc(1, domain_len);
		
		if (normalized) {
			// Normalize domain name
			dns_unified(domain, normalized, domain_len);
			
			// Add to JSON array
			struct json_object *domain_obj = json_object_new_string(normalized);
			if (domain_obj) {
				json_object_array_add(domain_array, domain_obj);
			}
			
			free(normalized);
		}
		
		domain = strtok_r(NULL, ",", &saveptr);
	}

	free(domains_copy);
	
	// Add array to main JSON object
	json_object_object_add(j_ctl_req, "custom_domains", domain_array);
}

/**
 * @brief Creates a new work connection structure
 *
 * Allocates and initializes a new work connection structure with NULL run_id.
 *
 * @return struct work_conn* Pointer to newly allocated work connection structure,
 *         or NULL if memory allocation fails
 */
struct work_conn *new_work_conn()
{
	struct work_conn *work_c = calloc(1, sizeof(struct work_conn));
	if (!work_c) {
		debug(LOG_ERR, "Failed to allocate work connection");
		return NULL;
	}
	
	work_c->run_id = NULL;
	return work_c;
}

/**
 * @brief Generates an authentication key from a token and timestamp
 *
 * @param token Input token string, can be NULL
 * @param timestamp Pointer to store the current timestamp
 * @return char* Generated auth key string or NULL on failure. Caller must free.
 *
 * The function:
 * 1. Gets current timestamp
 * 2. Creates seed by concatenating token and timestamp
 * 3. Calculates MD5 hash of seed
 * 4. Converts hash to hex string
 */
char *get_auth_key(const char *token, time_t *timestamp)
{
	if (!timestamp) {
		return NULL;
	}

	// Get current timestamp
	*timestamp = time(NULL);

	// Create seed string
	char seed[128] = {0};
	int ret = snprintf(seed, sizeof(seed), "%s%ld", 
					  token ? token : "", *timestamp);
	if (ret < 0 || ret >= sizeof(seed)) {
		return NULL;
	}

	// Calculate MD5 hash
	uint8_t digest[16] = {0};
	if (calc_md5((const uint8_t *)seed, strlen(seed), digest) < 0) {
		return NULL;
	}

	// Allocate auth key buffer
	char *auth_key = malloc(33); // 32 hex chars + null terminator
	if (!auth_key) {
		return NULL;
	}

	// Convert hash to hex string
	for (int i = 0; i < 16; i++) {
		snprintf(auth_key + i * 2, 3, "%02x", digest[i]);
	}

	auth_key[32] = '\0';
	return auth_key;
}

/**
 * @brief Marshals login request data into a JSON string
 *
 * @param msg Pointer to store the resulting JSON string
 * @return size_t Number of bytes in marshaled string, 0 on failure
 */
size_t login_request_marshal(char **msg)
{
	if (!msg) return 0;

	// Create JSON object
	struct json_object *j_login_req = json_object_new_object();
	if (!j_login_req) return 0;

	// Get login config
	struct login *lg = get_common_login_config();
	if (!lg) {
		json_object_put(j_login_req);
		return 0;
	}

	// Generate new auth key
	struct common_conf *cf = get_common_config();
	char *auth_key = get_auth_key(cf->auth_token, &lg->timestamp);
	if (!auth_key) {
		json_object_put(j_login_req);
		return 0;
	}

	// Update privilege key
	SAFE_FREE(lg->privilege_key);
	lg->privilege_key = strdup(auth_key);
	if (!lg->privilege_key) {
		SAFE_FREE(auth_key);
		json_object_put(j_login_req);
		return 0;
	}

	// Add required fields
	JSON_MARSHAL_TYPE(j_login_req, "version", string, lg->version);
	JSON_MARSHAL_TYPE(j_login_req, "hostname", string, SAFE_JSON_STRING(lg->hostname));
	JSON_MARSHAL_TYPE(j_login_req, "os", string, lg->os);
	JSON_MARSHAL_TYPE(j_login_req, "arch", string, lg->arch);
	JSON_MARSHAL_TYPE(j_login_req, "privilege_key", string, lg->privilege_key);
	JSON_MARSHAL_TYPE(j_login_req, "pool_count", int, lg->pool_count);

	// Add timestamp based on architecture
	if (sizeof(time_t) == 4) {
		JSON_MARSHAL_TYPE(j_login_req, "timestamp", int, lg->timestamp);
	} else {
		JSON_MARSHAL_TYPE(j_login_req, "timestamp", int64, lg->timestamp);
	}

	// Add optional fields
	if (lg->user) {
		JSON_MARSHAL_TYPE(j_login_req, "user", string, lg->user);
	}
	if (lg->run_id) {
		JSON_MARSHAL_TYPE(j_login_req, "run_id", string, lg->run_id);
	}

	// Convert to string
	size_t nret = 0;
	const char *json_str = json_object_to_json_string(j_login_req);
	if (json_str && strlen(json_str) > 0) {
		*msg = strdup(json_str);
		if (*msg) {
			nret = strlen(json_str);
		}
	}

	// Cleanup
	json_object_put(j_login_req);
	SAFE_FREE(auth_key);
	
	return nret;
}

/**
 * @brief Marshals a proxy service configuration into a JSON string
 *
 * @param np_req Proxy service configuration structure
 * @param msg Pointer to store the resulting JSON string
 * @return Number of bytes in the marshaled string, 0 on failure
 */
int new_proxy_service_marshal(const struct proxy_service *np_req, char **msg)
{
	if (!np_req || !msg) return 0;

	struct json_object *j_np_req = json_object_new_object();
	if (!j_np_req) return 0;

	// Add basic proxy configuration
	JSON_MARSHAL_TYPE(j_np_req, "proxy_name", string, np_req->proxy_name);
	
	// Handle proxy type - normalize socks5/mstsc to tcp
	const char *proxy_type = (strcmp(np_req->proxy_type, "socks5") == 0 || 
							strcmp(np_req->proxy_type, "mstsc") == 0) ? 
							"tcp" : np_req->proxy_type;
	JSON_MARSHAL_TYPE(j_np_req, "proxy_type", string, proxy_type);

	// Add encryption and compression flags
	JSON_MARSHAL_TYPE(j_np_req, "use_encryption", boolean, np_req->use_encryption);
	JSON_MARSHAL_TYPE(j_np_req, "use_compression", boolean, np_req->use_compression);

	// Add group settings for specific proxy types
	if (strcmp(proxy_type, "tcp") == 0 || 
		strcmp(proxy_type, "http") == 0 ||
		strcmp(proxy_type, "https") == 0) {
		if (np_req->group) {
			JSON_MARSHAL_TYPE(j_np_req, "group", string, np_req->group);
		}
		if (np_req->group_key) {
			JSON_MARSHAL_TYPE(j_np_req, "group_key", string, np_req->group_key);
		}
	}

	// Handle FTP specific configuration
	if (is_ftp_proxy(np_req)) {
		JSON_MARSHAL_TYPE(j_np_req, "remote_data_port", int, np_req->remote_data_port);
	}

	// Handle domains and ports
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

	// Add subdomain
	JSON_MARSHAL_TYPE(j_np_req, "subdomain", string, SAFE_JSON_STRING(np_req->subdomain));

	// Handle locations array
	struct json_object *j_location_array = json_object_new_array();
	if (np_req->locations) {
		char *locations_copy = strdup(np_req->locations);
		if (locations_copy) {
			char *save_ptr = NULL;
			char *path = strtok_r(locations_copy, ",", &save_ptr);
			while (path) {
				json_object_array_add(j_location_array, json_object_new_string(path));
				path = strtok_r(NULL, ",", &save_ptr);
			}
			free(locations_copy);
		}
		json_object_object_add(j_np_req, "locations", j_location_array);
	} else {
		json_object_object_add(j_np_req, "locations", NULL);
		json_object_put(j_location_array);
	}

	// Add HTTP related fields
	JSON_MARSHAL_TYPE(j_np_req, "host_header_rewrite", string, SAFE_JSON_STRING(np_req->host_header_rewrite));
	JSON_MARSHAL_TYPE(j_np_req, "http_user", string, SAFE_JSON_STRING(np_req->http_user));
	JSON_MARSHAL_TYPE(j_np_req, "http_pwd", string, SAFE_JSON_STRING(np_req->http_pwd));

	// Convert to string
	const char *json_str = json_object_to_json_string(j_np_req);
	int nret = 0;
	if (json_str && strlen(json_str) > 0) {
		*msg = strdup(json_str);
		if (*msg) {
			nret = strlen(json_str);
		}
	}

	json_object_put(j_np_req);
	return nret;
}

/**
 * @brief Marshals work connection data into a JSON string
 *
 * Creates a JSON object containing work connection information and converts it to a string.
 * The resulting JSON string contains the "run_id" field from the work_conn structure.
 *
 * @param work_c Pointer to the work connection structure to marshal
 * @param msg    Pointer to char pointer that will store the resulting JSON string
 *
 * @return Length of the marshaled string on success, 0 on failure
 *         The caller is responsible for freeing the allocated string in *msg
 */
int new_work_conn_marshal(const struct work_conn *work_c, char **msg)
{
	if (!work_c || !msg) {
		return 0;
	}

	struct json_object *j_new_work_conn = json_object_new_object();
	if (!j_new_work_conn) {
		return 0;
	}

	// Add run_id field
	JSON_MARSHAL_TYPE(j_new_work_conn, "run_id", string, SAFE_JSON_STRING(work_c->run_id));

	// Convert to JSON string
	const char *json_str = json_object_to_json_string(j_new_work_conn);
	int nret = 0;
	
	if (json_str && strlen(json_str) > 0) {
		*msg = strdup(json_str);
		if (*msg) {
			nret = strlen(json_str);
		}
	}

	json_object_put(j_new_work_conn);
	return nret;
}

/**
 * @brief Unmarshal a JSON string into a new_proxy_response structure
 *
 * @param jres The JSON string to unmarshal. Must not be NULL.
 * @return struct new_proxy_response* Pointer to newly allocated response structure,
 *         or NULL if:
 *         - Input is NULL
 *         - JSON parsing fails
 *         - Required fields are missing 
 *         - Memory allocation fails
 *         
 * @note The returned structure must be freed by the caller
 */
struct new_proxy_response *new_proxy_resp_unmarshal(const char *jres) 
{
	if (!jres) return NULL;

	struct json_object *j_np_res = json_tokener_parse(jres);
	if (!j_np_res) return NULL;

	struct new_proxy_response *npr = calloc(1, sizeof(struct new_proxy_response));
	if (!npr) {
		json_object_put(j_np_res);
		return NULL;
	}

	// Get optional run_id field
	struct json_object *j_run_id = NULL;
	if (json_object_object_get_ex(j_np_res, "run_id", &j_run_id)) {
		const char *run_id = json_object_get_string(j_run_id);
		if (run_id && !(npr->run_id = strdup(run_id))) {
			goto error;
		}
	}

	// Get required remote_addr field
	struct json_object *j_remote_addr = NULL;
	if (!json_object_object_get_ex(j_np_res, "remote_addr", &j_remote_addr)) {
		goto error;
	}
	
	// Parse port from remote_addr
	const char *remote_addr = json_object_get_string(j_remote_addr);
	if (remote_addr) {
		const char *port = strrchr(remote_addr, ':');
		if (port) {
			npr->remote_port = atoi(port + 1);
		}
	}

	// Get required proxy_name field
	struct json_object *j_proxy_name = NULL;
	if (!json_object_object_get_ex(j_np_res, "proxy_name", &j_proxy_name) ||
		!(npr->proxy_name = strdup(json_object_get_string(j_proxy_name)))) {
		goto error;
	}

	// Get optional error field
	struct json_object *j_error = NULL;
	if (json_object_object_get_ex(j_np_res, "error", &j_error)) {
		const char *error = json_object_get_string(j_error);
		if (error && !(npr->error = strdup(error))) {
			goto error;
		}
	}

	json_object_put(j_np_res);
	return npr;

error:
	json_object_put(j_np_res);
	if (npr) {
		SAFE_FREE(npr->run_id);
		SAFE_FREE(npr->proxy_name);
		SAFE_FREE(npr->error);
		SAFE_FREE(npr);
	}
	return NULL;
}

/**
 * @brief Unmarshal a JSON string into a login_resp structure
 *
 * @param jres The JSON string to unmarshal. Must not be NULL.
 * @return struct login_resp* Pointer to newly allocated login_resp structure,
 *         or NULL if:
 *         - Input is NULL
 *         - JSON parsing fails
 *         - Required fields are missing
 *         - Memory allocation fails
 *         
 * @note The returned structure must be freed by the caller
 */
struct login_resp *login_resp_unmarshal(const char *jres)
{
	if (!jres) return NULL;

	struct json_object *j_lg_res = json_tokener_parse(jres);
	if (!j_lg_res) return NULL;

	struct login_resp *lr = calloc(1, sizeof(struct login_resp));
	if (!lr) {
		json_object_put(j_lg_res);
		return NULL;
	}

	// Get version field
	struct json_object *l_version = NULL;
	if (!json_object_object_get_ex(j_lg_res, "version", &l_version) ||
		!(lr->version = strdup(json_object_get_string(l_version)))) {
		goto error;
	}

	// Get run_id field
	struct json_object *l_run_id = NULL;
	if (!json_object_object_get_ex(j_lg_res, "run_id", &l_run_id) ||
		!(lr->run_id = strdup(json_object_get_string(l_run_id)))) {
		goto error;
	}

	// Get optional error field if present
	struct json_object *l_error = NULL;
	if (json_object_object_get_ex(j_lg_res, "error", &l_error)) {
		const char *error_str = json_object_get_string(l_error);
		if (error_str && !(lr->error = strdup(error_str))) {
			goto error;
		}
	}

	json_object_put(j_lg_res);
	return lr;

error:
	json_object_put(j_lg_res);
	if (lr) {
		SAFE_FREE(lr->version);
		SAFE_FREE(lr->run_id);
		SAFE_FREE(lr->error);
		SAFE_FREE(lr);
	}
	return NULL;
}

/**
 * @brief Unmarshals a start work connection response message from JSON string
 *
 * @param resp_msg The JSON string to unmarshal. Must not be NULL.
 * @return struct start_work_conn_resp* Pointer to newly allocated response structure,
 *         or NULL if:
 *         - Input is NULL
 *         - JSON parsing fails
 *         - Required fields are missing
 *         - Memory allocation fails
 *         
 * @note The returned structure must be freed by the caller
 */
struct start_work_conn_resp *start_work_conn_resp_unmarshal(const char *resp_msg)
{
	if (!resp_msg) return NULL;

	struct json_object *j_start_w_res = json_tokener_parse(resp_msg);
	if (!j_start_w_res) return NULL;

	struct start_work_conn_resp *sr = calloc(1, sizeof(struct start_work_conn_resp));
	if (!sr) {
		json_object_put(j_start_w_res);
		return NULL;
	}

	struct json_object *pn = NULL;
	if (!json_object_object_get_ex(j_start_w_res, "proxy_name", &pn)) {
		goto error;
	}

	const char *proxy_name = json_object_get_string(pn);
	if (!proxy_name) {
		goto error;
	}

	sr->proxy_name = strdup(proxy_name);
	if (!sr->proxy_name) {
		goto error;
	}

	json_object_put(j_start_w_res);
	return sr;

error:
	json_object_put(j_start_w_res);
	if (sr) {
		SAFE_FREE(sr->proxy_name);
		SAFE_FREE(sr);
	}
	return NULL;
}

/**
 * @brief Unmarshal a JSON string into a control_response structure
 *
 * This function parses a JSON string and creates a control_response structure
 * containing the unmarshaled data. The JSON should have the following fields:
 * - type: integer value
 * - code: integer value  
 * - msg: string value
 *
 * @param jres The JSON string to unmarshal. Must not be NULL.
 * @return struct control_response* Pointer to newly allocated control_response structure
 *         containing the unmarshaled data, or NULL if:
 *         - Input is NULL
 *         - JSON parsing fails
 *         - Memory allocation fails
 *         - Required fields are missing
 *         - Message string cannot be duplicated
 *
 * @note The returned structure must be freed using control_response_free()
 */
struct control_response *control_response_unmarshal(const char *jres)
{
	if (!jres) return NULL;

	struct json_object *j_ctl_res = json_tokener_parse(jres);
	if (!j_ctl_res) return NULL;

	struct control_response *ctl_res = calloc(1, sizeof(struct control_response));
	if (!ctl_res) {
		json_object_put(j_ctl_res);
		return NULL;
	}

	// Get type field
	struct json_object *jtype = NULL;
	if (!json_object_object_get_ex(j_ctl_res, "type", &jtype)) {
		goto error;
	}
	ctl_res->type = json_object_get_int(jtype);

	// Get code field 
	struct json_object *jcode = NULL;
	if (!json_object_object_get_ex(j_ctl_res, "code", &jcode)) {
		goto error;
	}
	ctl_res->code = json_object_get_int(jcode);

	// Get msg field
	struct json_object *jmsg = NULL;
	if (!json_object_object_get_ex(j_ctl_res, "msg", &jmsg)) {
		goto error;
	}
	const char *msg_str = json_object_get_string(jmsg);
	if (!msg_str) {
		goto error;
	}
	ctl_res->msg = strdup(msg_str);
	if (!ctl_res->msg) {
		goto error;
	}

	json_object_put(j_ctl_res);
	return ctl_res;

error:
	json_object_put(j_ctl_res);
	control_response_free(ctl_res);
	return NULL;
}

/**
 * @brief Frees memory allocated for a control response structure
 *
 * This function safely deallocates memory for:
 * - The message string within the control response
 * - The control response structure itself
 *
 * @param res Pointer to the control_response structure to be freed
 * @note Function checks for NULL pointer before attempting to free memory
 */
void control_response_free(struct control_response *res)
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
