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

/** @file login.h
    @brief xfrp login header
    @author Copyright (C) 2016 Dengfeng Liu <liu_df@qq.com>
*/

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
	char		*metas;
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
int login_resp_check(struct login_resp *lr);

#endif //_LOGIN_H_
