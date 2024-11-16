
#ifndef XFRPC_LOGIN_H_
#define XFRPC_LOGIN_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <time.h>

#include "uthash.h"

// Login configuration structure
typedef struct login {
	// Version information
	char    *version;
	// System information
	char    *hostname;
	char    *os;
	char    *arch;
	// User credentials
	char    *user;
	char    *privilege_key;
	// Session information
	time_t  timestamp;
	char    *run_id;
	char    *metas;
	int     pool_count;
	// Login status
	int     logged;     // 0: not logged in, 1: logged in
} login_t;

// Login response structure
typedef struct login_resp {
	char    *version;
	char    *run_id;
	char    *error;
} login_resp_t;

// Function declarations
void init_login(void);
char *get_run_id(void);
login_t *get_common_login_config(void);
int is_logged(void);
int login_resp_check(login_resp_t *lr);

#endif /* XFRPC_LOGIN_H_ */
