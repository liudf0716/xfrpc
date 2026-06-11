// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 *
 * NAT Hole Punching module for XTCP P2P traversal.
 * Implements STUN discovery, NAT classification, and UDP hole-punch protocol.
 */

#ifndef XFRPC_NATHOLE_H
#define XFRPC_NATHOLE_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>
#include <event2/event.h>
#include <event2/bufferevent.h>

/* ---- STUN constants ---- */
#define STUN_PORT            3478
#define STUN_MAX_SERVERS     4
#define STUN_TIMEOUT_MS      3000
#define STUN_MAGIC_COOKIE    0x2112A442
#define STUN_TXID_LEN        12
#define STUN_MAX_ADDRS       8

/* STUN message types */
#define STUN_BINDING_REQUEST  0x0001
#define STUN_BINDING_RESPONSE 0x0101

/* STUN attribute types */
#define STUN_ATTR_MAPPED_ADDR     0x0001
#define STUN_ATTR_RESPONSE_ADDR   0x0002
#define STUN_ATTR_CHANGE_REQUEST  0x0003
#define STUN_ATTR_CHANGED_ADDR    0x0004
#define STUN_ATTR_XOR_MAPPED_ADDR 0x0020
#define STUN_ATTR_OTHER_ADDR      0x802C

/* ---- NAT types ---- */
#define NAT_TYPE_EASY  "EasyNAT"
#define NAT_TYPE_HARD  "HardNAT"

#define NAT_BEHAVIOR_NO_CHANGE    "BehaviorNoChange"
#define NAT_BEHAVIOR_PORT_CHANGED "BehaviorPortChanged"
#define NAT_BEHAVIOR_IP_CHANGED   "BehaviorIPChanged"
#define NAT_BEHAVIOR_BOTH_CHANGED "BehaviorBothChanged"

/* ---- Detect roles ---- */
#define DETECT_ROLE_SENDER   "sender"
#define DETECT_ROLE_RECEIVER "receiver"

/* ---- Max limits ---- */
#define MAX_MAPPED_ADDRS    8
#define MAX_ASSISTED_ADDRS  16
#define MAX_CANDIDATE_ADDRS 8

/* Default STUN servers */
#define DEFAULT_STUN_SERVER_1 "stun.miwifi.com"
#define DEFAULT_STUN_SERVER_2 "stun.qq.com"

/* ---- Structures ---- */

/* A discovered external address from STUN */
struct stun_addr {
	char    addr[64];   /* "IP:port" string */
};

/* STUN discovery result */
struct stun_result {
	struct stun_addr    addrs[MAX_MAPPED_ADDRS];
	int                 addr_count;
	struct sockaddr_in  local_addr;    /* local UDP address used */
};

/* NAT feature classification */
struct nat_feature {
	char    nat_type[16];       /* "EasyNAT" or "HardNAT" */
	char    behavior[32];       /* "BehaviorNoChange" etc */
	int     ports_difference;   /* max_port - min_port */
	bool    regular_ports_change;
	bool    public_network;
};

/* NatHoleSid message for UDP hole-punch packets */
struct nathole_sid_msg {
	char    *transaction_id;
	char    *sid;
	bool     response;
	char    *nonce;
};

/* Detect behavior from NatHoleResp */
struct detect_behavior {
	int     mode;
	char    role[16];           /* "sender" or "receiver" */
	int     ttl;
	int     send_delay_ms;
	int     read_timeout_ms;
	int     send_random_ports;
	int     listen_random_ports;
	/* Candidate port ranges */
	struct {
		int from;
		int to;
	} candidate_ports[16];
	int     candidate_ports_count;
};

/* NatHoleResp message */
struct nathole_resp {
	char                *transaction_id;
	char                *sid;
	char                *protocol;
	char                *candidate_addrs[MAX_CANDIDATE_ADDRS];
	int                  candidate_addrs_count;
	char                *assisted_addrs[MAX_CANDIDATE_ADDRS];
	int                  assisted_addrs_count;
	struct detect_behavior behavior;
	char                *error;
};

/* ---- STUN Discovery ---- */

/**
 * @brief Discover external addresses using STUN servers
 *
 * Sends STUN Binding Requests to STUN servers and collects
 * external (mapped) addresses. Uses 2 STUN servers to get
 * at least 2 addresses for NAT classification.
 *
 * @param stun_servers Array of STUN server hostnames (NULL-terminated)
 * @param local_addr   Local address to bind (NULL for any)
 * @param result       Output discovery result
 * @return 0 on success, -1 on failure
 */
int stun_discover(const char **stun_servers, const char *local_addr,
				  struct stun_result *result);

/**
 * @brief Discover external addresses using an existing UDP socket.
 *
 * Same as stun_discover() but uses the caller's socket instead of
 * creating a new one. The socket is NOT closed on return.
 * This preserves the NAT mapping for subsequent hole-punching.
 *
 * @param sock         Existing UDP socket fd
 * @param stun_servers Array of STUN server hostnames (NULL-terminated)
 * @param result       Output discovery result
 * @return 0 on success, -1 on failure
 */
int stun_discover_on_socket(int sock, const char **stun_servers,
			    struct stun_result *result);

/**
 * @brief Classify NAT type based on discovered external addresses
 *
 * Compares external addresses from STUN to determine NAT behavior:
 * - EasyNAT: same IP, same port
 * - HardNAT + port changed: different ports
 * - HardNAT + IP changed: different IPs
 * - HardNAT + both changed: different IPs and ports
 *
 * @param addrs      Array of external address strings
 * @param addr_count Number of addresses
 * @param local_ips  Array of local IP strings (for public network detection)
 * @param local_count Number of local IPs
 * @param feature    Output NAT feature classification
 * @return 0 on success, -1 on failure
 */
int classify_nat_feature(const char **addrs, int addr_count,
						 const char **local_ips, int local_count,
						 struct nat_feature *feature);

/* ---- UDP Hole Punching ---- */

/**
 * @brief Encode a NatHoleSid message into an encrypted UDP packet
 *
 * Format: [16-byte random IV][AES-128-CFB encrypted data]
 * Encrypted data: [type_byte='5'][JSON content]
 * Key derivation: PBKDF2(secret_key, salt="crypto", iter=64, keylen=16, SHA1)
 *
 * @param msg       The NatHoleSid message to encode
 * @param secret_key The shared secret key
 * @param out_buf   Output buffer (caller must free)
 * @param out_len   Output length
 * @return 0 on success, -1 on failure
 */
int nathole_encode_sid(const struct nathole_sid_msg *msg,
					   const char *secret_key,
					   uint8_t **out_buf, size_t *out_len);

/**
 * @brief Decode a UDP packet into a NatHoleSid message
 *
 * @param data       Raw UDP packet data
 * @param data_len   Length of data
 * @param secret_key The shared secret key
 * @param msg        Output message (caller must free strings)
 * @return 0 on success, -1 on failure
 */
int nathole_decode_sid(const uint8_t *data, size_t data_len,
					   const char *secret_key,
					   struct nathole_sid_msg *msg);

/**
 * @brief Free strings allocated in a NatHoleSid message
 */
void nathole_sid_msg_free(struct nathole_sid_msg *msg);

/**
 * @brief Free strings allocated in a NatHoleResp message
 */
void nathole_resp_free(struct nathole_resp *resp);

/* ---- Local IP Discovery ---- */

/**
 * @brief List local network interface IP addresses
 *
 * @param ips      Output array of IP strings
 * @param max_ips  Maximum number of IPs to return
 * @return Number of IPs found
 */
int list_local_ips(char ips[][64], int max_ips);

/* ---- Auth Key ---- */

/**
 * @brief Generate auth key for NatHoleVisitor/NatHoleClient messages
 * auth_key = MD5(secret_key + timestamp_string)
 *
 * @param secret_key The shared secret key
 * @param timestamp  Current timestamp
 * @param out_key    Output hex string (32 chars + null, caller must free)
 * @return 0 on success, -1 on failure
 */
int nathole_auth_key(const char *secret_key, time_t timestamp, char **out_key);

/* ---- Transaction ID ---- */

/**
 * @brief Generate a random transaction ID for NatHole messages
 * Format: "<unix_timestamp><random_hex>"
 *
 * @param buf Output buffer (at least 32 bytes)
 */
void nathole_gen_transaction_id(char *buf, size_t buf_len);

#endif /* XFRPC_NATHOLE_H */
