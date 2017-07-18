#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <time.h>

#include <syslog.h>
#include <sys/utsname.h>

#include "ini.h"
#include "uthash.h"
#include "config.h"
#include "client.h"
#include "debug.h"
#include "msg.h"
#include "version.h"
#include "login.h"
#include "utils.h"

static struct login 		*c_login;

char *get_run_id()
{
	return c_login->run_id;
}

struct login *get_common_login_config()
{
	return c_login;
}

int is_logged()
{
	return c_login->logged;
}

void init_login()
{
	if (! c_login) 
		c_login = calloc(sizeof(struct login), 1);

	assert(c_login);

	struct common_conf *c_conf = get_common_config();
	assert(c_conf);

	struct utsname uname_buf;
	if (uname(&uname_buf)) {
		return;
	}

	c_login->version 		= strdup(PROTOCOL_VERESION);
	assert(c_login->version);
	c_login->hostname 		= NULL;
	c_login->os 			= strdup(uname_buf.sysname);
	assert(c_login->os);
	c_login->arch 			= strdup(uname_buf.machine);
	assert(c_login->arch);
	c_login->user 			= NULL;

	c_login->timestamp 		= 0;
	c_login->run_id 		= NULL;
	c_login->pool_count 	= 1;
	c_login->privilege_key 	= NULL;
	c_login->user			= c_conf->user;

	c_login->logged 		= 0;

	/* start to init login->run_id */
	char ifname[16] = {0};
	if(get_net_ifname(ifname, 16)){
		debug(LOG_ERR, "error: get device sign ifname failed!");
		exit(0);
	}

	char if_mac[64] = {0};
	if(get_net_mac(ifname, if_mac, sizeof(if_mac))) {
		debug(LOG_ERR, "error: Hard ware MAC address of [%s] get failed!", ifname);
		exit(0);
	}

	c_login->run_id = strdup(if_mac);
	assert(c_login->run_id);
}

int login_resp_check(struct login_resp *lr)
{
	if (lr->run_id == NULL || strlen(lr->run_id) <= 1) {
		if (lr->error && strlen(lr->error) > 0) {
			debug(LOG_ERR, "login response error: %s", lr->error);
		}
		debug(LOG_ERR, "login falied!");
		c_login->logged = 0;
	} else {
		c_login->logged = 1;
		debug(LOG_DEBUG, "xfrp login response: run_id: [%s], version: [%s]", 
			lr->run_id, 
			lr->version);
		SAFE_FREE(c_login->run_id);

		c_login->run_id = strdup(lr->run_id);
		assert(c_login->run_id);
	}

	return c_login->logged;
}