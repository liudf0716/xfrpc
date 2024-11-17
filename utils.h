
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef XFRPC_UTILS_H_
#define XFRPC_UTILS_H_

#include <stddef.h>

/**
 * Structure to hold dynamic string data for curl operations
 */
struct mycurl_string {
	char    *ptr;   /* Pointer to string data */
	size_t  len;    /* Length of string */
};

/**
 * Sleep for specified seconds and microseconds
 * @param s Seconds to sleep
 * @param u Microseconds to sleep
 */
void s_sleep(unsigned int s, unsigned int u);

/**
 * Validate an IP address string
 * @param ip_address IP address string to validate
 * @return 1 if valid, 0 if invalid
 */
int is_valid_ip_address(const char *ip_address);

/**
 * Display available network interface names
 * @return 0 on success, negative value on failure
 */
int show_net_ifname(void);

/**
 * Get network interface name
 * @param if_buf Buffer to store interface name
 * @param blen Length of buffer
 * @return 0 on success, negative value on failure
 */
int get_net_ifname(char *if_buf, int blen);

/**
 * Get MAC address of specified network interface
 * @param net_if_name Network interface name
 * @param mac Buffer to store MAC address
 * @param mac_len Length of MAC buffer
 * @return 0 on success, negative value on failure
 */
int get_net_mac(const char *net_if_name, char *mac, int mac_len);

/**
 * Unify DNS name format
 * @param dname Original DNS name
 * @param udname_buf Buffer to store unified DNS name
 * @param udname_buf_len Length of buffer
 * @return 0 on success, negative value on failure
 */
int dns_unified(const char *dname, char *udname_buf, int udname_buf_len);

#endif // XFRPC_UTILS_H_
