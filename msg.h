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

/** @file msg.h
    @brief xfrp msg struct
    @author Copyright (C) 2016 Dengfeng Liu <liudengfeng@kunteng.org>
*/


struct general_response {
	int		code;
	char	*msg;
};

// messages between control connections of frpc and frps
struct control_request {
	int		type;
	char	*proxy_name;
	char	*auth_key;
	int		use_encryption;
	int		use_gzip;
	int		pool_count;
	
	int		privilege_mode;
	char	*privilege_key;
	char	*proxy_type;
	int		remote_port;
	char	**custom_domains;
	char	**locations;
	char	*host_header_rewrite;
	char	*http_username;
	char	*http_password;
	char	*subdomain;
	long	timestamp;
};


struct control_response {
	int		type;
	int		code;
	char	*msg;
};

// tranlate control request to json string
char *control_request_marshal(const struct control_request *req);

// parse json string to control response
int control_response_unmarshal(const char *jres, struct control_response *res);
