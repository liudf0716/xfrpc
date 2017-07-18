#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <errno.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <linux/if_link.h>

#include "utils.h"

// s_sleep using select instead of sleep
// s: second, u: usec 10^6usec = 1s
void s_sleep(unsigned int s, unsigned int u)
{
	struct timeval timeout;

	timeout.tv_sec = s;
	timeout.tv_usec = u;
	select(0, NULL, NULL, NULL, &timeout);
}

// is_valid_ip_address:
// return 0:ipaddress unlegal
int is_valid_ip_address(const char *ip_address) 
{
    struct sockaddr_in sa;
    int result = inet_pton(AF_INET, ip_address, &(sa.sin_addr));
	return result;
}

//	net_if_name: name of network interface, e.g. br-lan
//	return: 1: error 0:get succeed
int get_net_mac(char *net_if_name, char *mac, int mac_len) {
	int ret = 1;
	int i = 0;
	int sock = 0;

	if (mac_len < 12 || net_if_name == NULL) {
		return 1;
	}
	struct ifreq ifreq;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	if( sock < 0 ) {
		perror("error sock");
		goto OUT;
	}

	strncpy(ifreq.ifr_name, net_if_name, IFNAMSIZ);
	if( ioctl(sock, SIOCGIFHWADDR,&ifreq) < 0 ) {
		perror("error ioctl");
		goto OUT;
	}

	for( i = 0; i < 6; i++ ){
		snprintf(mac+2*i, mac_len - 2*i, "%02X", 
			(unsigned char)ifreq.ifr_hwaddr.sa_data[i]);
	}
	mac[strlen(mac)] = 0;
	ret =  0;

OUT:
	close(sock);
	return ret;
}

// return: -1: network interface check failed; other: ifname numbers 
int show_net_ifname()
{
	struct ifaddrs *ifaddr, *ifa;
	int family, s, n;
	char host[NI_MAXHOST];

	if (getifaddrs(&ifaddr) == -1) {
	   perror("getifaddrs");
	   exit(EXIT_FAILURE);
	}

	/* Walk through linked list, maintaining head pointer so we
	  can free list later */

	for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
	    if (ifa->ifa_addr == NULL) continue;

	    family = ifa->ifa_addr->sa_family;

		/* Display interface name and family (including symbolic
		form of the latter for the common families) */
		 
		printf("%-8s %s (%d)\n",
		      ifa->ifa_name,
		      (family == AF_PACKET) ? "AF_PACKET" :
		      (family == AF_INET) ? "AF_INET" :
		      (family == AF_INET6) ? "AF_INET6" : "???",
		      family);

	   /* For an AF_INET* interface address, display the address */

	   if (family == AF_INET || family == AF_INET6) {
	       s = getnameinfo(ifa->ifa_addr,
	               (family == AF_INET) ? sizeof(struct sockaddr_in) :
	                                     sizeof(struct sockaddr_in6),
	               host, NI_MAXHOST,
	               NULL, 0, NI_NUMERICHOST);
	       if (s != 0) {
	           printf("getnameinfo() failed: %s\n", gai_strerror(s));
	           exit(EXIT_FAILURE);
	       }

	       printf("\t\taddress: <%s>\n", host);

	   } else if (family == AF_PACKET && ifa->ifa_data != NULL) {
	       struct rtnl_link_stats *stats = (struct rtnl_link_stats *)ifa->ifa_data;

	       printf("\t\ttx_packets = %10u; rx_packets = %10u\n"
	              "\t\ttx_bytes   = %10u; rx_bytes   = %10u\n",
	              stats->tx_packets, stats->rx_packets,
	              stats->tx_bytes, stats->rx_bytes);
	   }
	}

	freeifaddrs(ifaddr);
	return 0;
}

// return: 0: network interface get succeed
int get_net_ifname(char *if_buf, int blen)
{
	if (NULL == if_buf || blen < 8) return -1;

	struct ifaddrs *ifaddr, *ifa;
	int family, n;
	int ret = 1;
	if (getifaddrs(&ifaddr) == -1) {
	   perror("getifaddrs");
	   exit(EXIT_FAILURE);
	}

	int found = 0;
	char tmp_if_buf[16];
	memset(tmp_if_buf, 0, sizeof(tmp_if_buf));
	/* Walk through linked list, maintaining head pointer so we
	  can free list later */
	for (ifa = ifaddr, n = 0; ifa != NULL; ifa = ifa->ifa_next, n++) {
	    if (ifa->ifa_addr == NULL) continue;

	    family = ifa->ifa_addr->sa_family;

		if (family == AF_INET) {
			// for LEDE/OpenWRT embedded router os
			if (strcmp(ifa->ifa_name, "br-lan") == 0) {
				found = 1;
				break;
			}

			if (strcmp(ifa->ifa_name, "lo") != 0 ) {
				strncpy(tmp_if_buf, ifa->ifa_name, 16);
			}
		}
	}

	if (found) {
		strncpy(if_buf, ifa->ifa_name, blen);
		ret = 0;
	} else if (tmp_if_buf[0] != 0) {
		strncpy(if_buf, tmp_if_buf, blen);
		ret = 0;
	}

	freeifaddrs(ifaddr);
	return ret;
}