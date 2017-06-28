#ifndef _LOGIN_H_
#define _LOGIN_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#include "uthash.h"


void init_login();
char *get_run_id();
struct login *get_common_login_config();
int is_logged();

#endif //_LOGIN_H_