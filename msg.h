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
type ControlReq struct {
	Type          int64  `json:"type"`
	ProxyName     string `json:"proxy_name"`
	AuthKey       string `json:"auth_key"`
	UseEncryption bool   `json:"use_encryption"`
	UseGzip       bool   `json:"use_gzip"`
	PoolCount     int64  `json:"pool_count"`

	// configures used if privilege_mode is enabled
	PrivilegeMode     bool     `json:"privilege_mode"`
	PrivilegeKey      string   `json:"privilege_key"`
	ProxyType         string   `json:"proxy_type"`
	RemotePort        int64    `json:"remote_port"`
	CustomDomains     []string `json:"custom_domains, omitempty"`
	Locations         []string `json:"locations"`
	HostHeaderRewrite string   `json:"host_header_rewrite"`
	HttpUserName      string   `json:"http_username"`
	HttpPassWord      string   `json:"http_password"`
	SubDomain         string   `json:"subdomain"`
	Timestamp         int64    `json:"timestamp"`
}

struct control_request {
};


struct control_response {
	int		type;
	int		code;
	char	*msg;
};
