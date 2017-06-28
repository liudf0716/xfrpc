#ifndef _LOGIN_H_
#define _LOGIN_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#include "uthash.h"

struct login {
	char		*version;
	char		*hostname;
	char 		*os;
	char		*arch;
	char 		*user;
	char 		*privilege_key;
	long int 	timestamp;
	char 		*run_id;
	int 		pool_count;

	/* fields not need json marshal */
	int			logged;		//0 not login 1:logged
};

struct login_resp {
	char 	*version;
	char	*run_id;
	char 	*error;
};

void init_login();
char *get_run_id();
struct login *get_common_login_config();
int is_logged();

#endif //_LOGIN_H_