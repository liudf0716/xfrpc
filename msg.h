

// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef XFRPC_MSG_H
#define XFRPC_MSG_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <inttypes.h>

#include "client.h"
#include "common.h"

#define TYPE_LEN 1 //byte, char

#define MSG_TYPE_I 	0
#define MSG_LEN_I 	1
#define MSG_DATA_I	9

// msg_type match frp v0.10.0
enum msg_type {
	TypeLogin                 = 'o',
	TypeLoginResp             = '1',
	TypeNewProxy              = 'p',
	TypeNewProxyResp          = '2',
	TypeCloseProxy            = 'c',
	TypeNewWorkConn           = 'w',
	TypeReqWorkConn           = 'r',
	TypeStartWorkConn         = 's',
	TypeNewVisitorConn        = 'v',
	TypeNewVisitorConnResp    = '3',
	TypePing                  = 'h',
	TypePong                  = '4',
	TypeUDPPacket             = 'u',
	TypeNatHoleVisitor        = 'i',
	TypeNatHoleClient         = 'n',
	TypeNatHoleResp           = 'm',
	TypeNatHoleClientDetectOK = 'd',
	TypeNatHoleSid            = '5',
	TypeNatHoleReport         = '6',
};

// General response structure for basic server responses
struct general_response {
	int     code;       // Response code
	char    *msg;       // Response message
};

// Control response structure for server control messages
struct control_response {
	int     type;       // Control message type
	int     code;       // Response code
	char    *msg;       // Response message
};

// Response structure for new proxy requests
struct new_proxy_response {
	char    *run_id;        // Unique run identifier
	char    *proxy_name;    // Name of the proxy
	char    *error;         // Error message if any
	int     remote_port;    // Remote port number
};

// Structure for work connection information
struct work_conn {
	char    *run_id;        // Unique run identifier
};

// Structure for UDP address information
struct udp_addr {
	char    *addr;          // IP address
	int     port;           // Port number
	char    *zone;          // Network zone
};

// Structure for UDP packet data
struct udp_packet {
	char            *content;    // Base64 encoded content
	struct udp_addr *laddr;     // Local address
	struct udp_addr *raddr;     // Remote address
};

// Header structure for all messages with packed attribute to ensure exact memory layout
struct __attribute__((__packed__)) msg_hdr {
	char        type;       // Message type identifier
	uint64_t    length;     // Length of the data payload
	uint8_t     data[];     // Flexible array member for payload
};

// Response structure for start work connection requests
struct start_work_conn_resp {
	char    *proxy_name;    // Name of the proxy for the work connection
};

// Marshalling functions (Convert structures to messages)
int new_udp_packet_marshal(const struct udp_packet *udp, char **msg);
int new_proxy_service_marshal(const struct proxy_service *np_req, char **msg);
int new_work_conn_marshal(const struct work_conn *work_c, char **msg);
size_t login_request_marshal(char **msg);

// Authentication helper
char *get_auth_key(const char *token, time_t *timestamp);

// Unmarshalling functions (Parse JSON to structures)
struct new_proxy_response *new_proxy_resp_unmarshal(const char *jres);
struct login_resp *login_resp_unmarshal(const char *jres);
struct start_work_conn_resp *start_work_conn_resp_unmarshal(const char *resp_msg);
struct control_response *control_response_unmarshal(const char *jres);
struct udp_packet *udp_packet_unmarshal(const char *jres);

// Object creation
struct work_conn *new_work_conn(void);

// Cleanup functions
void udp_packet_free(struct udp_packet *udp);
void control_response_free(struct control_response *res);
void new_proxy_resp_free(struct new_proxy_response *npr);

/* ---- NatHole message structures ---- */

/* NatHoleVisitor: visitor → server (via TCP control connection) */
struct nathole_visitor_msg {
	char    *transaction_id;
	char    *proxy_name;
	int      pre_check;
	char    *protocol;
	char    *sign_key;
	int64_t  timestamp;
	char   **mapped_addrs;
	int      mapped_addrs_count;
	char   **assisted_addrs;
	int      assisted_addrs_count;
};

/* NatHoleClient: client → server (via TCP control connection) */
struct nathole_client_msg {
	char    *transaction_id;
	char    *proxy_name;
	char    *sid;
	char   **mapped_addrs;
	int      mapped_addrs_count;
	char   **assisted_addrs;
	int      assisted_addrs_count;
};

/* NatHoleResp: server → visitor/client (via TCP control connection) */
struct nathole_resp_msg {
	char    *transaction_id;
	char    *sid;
	char    *protocol;
	char   **candidate_addrs;
	int      candidate_addrs_count;
	char   **assisted_addrs;
	int      assisted_addrs_count;
	/* detect_behavior */
	int      behavior_mode;
	char    *behavior_role;
	int      behavior_ttl;
	int      behavior_send_delay_ms;
	int      behavior_read_timeout_ms;
	int      behavior_send_random_ports;
	int      behavior_listen_random_ports;
	/* candidate_ports: "from-to" pairs */
	int     *candidate_ports_from;
	int     *candidate_ports_to;
	int      candidate_ports_count;
	char    *error;
};

/* NatHoleReport: visitor/client → server (via TCP control connection) */
struct nathole_report_msg {
	char    *sid;
	int      success;
};

/* NatHole message marshalling/unmarshalling */
int nathole_visitor_marshal(const struct nathole_visitor_msg *msg, char **out);
int nathole_report_marshal(const struct nathole_report_msg *msg, char **out);

struct nathole_resp_msg *nathole_resp_unmarshal(const char *json_str);
void nathole_resp_msg_free(struct nathole_resp_msg *msg);

void nathole_visitor_msg_free(struct nathole_visitor_msg *msg);
void nathole_client_msg_free(struct nathole_client_msg *msg);

#endif
