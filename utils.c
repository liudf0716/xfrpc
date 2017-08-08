#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <errno.h>
#include <ctype.h>

#include <net/if.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <linux/if_link.h>
#include <curl/curl.h>
#include <curl/easy.h>

#include "utils.h"

/* curl define */
// curl methods 
#define GET 0
#define POST 1

#define CURL_DEBUG 0

#define CURL_OK 0x900
#define CURL_TIMEOUT_SET_ERR 0x901
#define CURL_FILE_DEL_ERR 0x902
#define CURL_FILE_OPEN_ERR 0x903
#define CURL_PERFORM_UNHANDLED_ERR 0x904
#define CURL_HTTP_200 0x905
#define CURL_HTTP_404 0x906
#define CURL_HTTP_OTHER 0x999

struct mycurl_string {
	char *ptr;
	size_t len;
};

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
		} else if (family == AF_PACKET && 
			ifa->ifa_data != NULL && 
			strcmp(ifa->ifa_name, "lo") != 0) { // skip local loop interface
			
			strncpy(tmp_if_buf, ifa->ifa_name, 16);
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

// e.g. wWw.Baidu.com/China will be trans into www.baidu.com/China
// return: 0:check and trant succeed, 1:failed or domain name is invalid
int dns_unified(const char *dname, char *udname_buf, int udname_buf_len)
{
	if (! dname || ! udname_buf || udname_buf_len < strlen(dname)+1)
		return 1;
	
	int has_dot = 0;
	int dlen = strlen(dname);
	int i = 0;
	for(i=0; i<dlen; i++) {
		if(dname[i] == '/')
			break;

		if (dname[i] == '.' && i != dlen-1)
			has_dot = 1;

		udname_buf[i] = tolower(dname[i]);
	}

	if (! has_dot)	//domain name should have 1 dot leastly
		return 1;

	return 0;
}

static int dl_progress(void *clientp, 
						double dltotal, 
						double dlnow, 
						double ultotal, 
						double ulnow) {
	// if there something to show while download or URL get, complate this func
	// e.g.:

    // if (dlnow && dltotal)
    //     printf("dl:%3.0f%%\r",100*dlnow/dltotal); //shenzi prog-mon 
	// //	printf("dl:%3.0f\r",100*dlnow/dltotal); //shenzi prog-mon 
    // fflush(stdout);

    return 0;
}

static size_t write_to_mycurl_string(void *buffer, 
									const size_t size, 
									const size_t nmemb, 
									struct mycurl_string *s) {
	size_t new_len = s->len + size*nmemb;
	// s->ptr = realloc(s->ptr, new_len + 1); // realloc is NOT recommended
	size_t buffer_len = new_len + 1;
	char *tmp_p = calloc(1, buffer_len);
	if (tmp_p == NULL) {
		return 0;
	}

	memcpy(tmp_p, s->ptr, s->len);
	free(s->ptr);
	s->ptr = tmp_p;
	memcpy(s->ptr + s->len, buffer, size*nmemb);

	return size*nmemb;
}

int net_visit(const char *url, 
			struct mycurl_string *s,
			int method,
			char *post_buf,
			long timeout, 
			int *state_code,
			double *down_size) {
	CURL *curl;
	CURLcode curl_retval;
	long http_response;
	double dl_size;
	int ret = 1;

    long dl_lowspeed_bytes = 1000; //1K
	*state_code = CURL_OK;
    long dl_lowspeed_time = 60; //sec
	if (timeout <= 0) {
		*state_code = CURL_TIMEOUT_SET_ERR;
		return ret;
	}

	curl = curl_easy_init();
	if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, url);
        /*callbacks*/
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_to_mycurl_string);
        curl_easy_setopt(curl, CURLOPT_PROGRESSFUNCTION, dl_progress);
        curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 30);
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_LIMIT, dl_lowspeed_bytes); //bytes/sec
        curl_easy_setopt(curl, CURLOPT_LOW_SPEED_TIME, dl_lowspeed_time); 
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, s);
        curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1); // handle 302 and 301

		if (method == POST) {
			char *self_post_buf = post_buf == NULL ? "/0":post_buf;
			curl_easy_setopt(curl, CURLOPT_POSTFIELDS, self_post_buf);
		}
#if CURL_DEBUG
        curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
#endif
        if(CURLE_OK != (curl_retval = curl_easy_perform(curl))) {
			switch(curl_retval) {
				default: 
					*state_code = curl_retval;
			};

            curl_easy_getinfo(curl, CURLINFO_CONTENT_LENGTH_DOWNLOAD, &dl_size);
			*down_size = dl_size;
            curl_retval=curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_response);

            switch(http_response){
				case 200:
					*state_code = CURL_HTTP_200;
					break;
				case 404:
					ret = 1;
					break;
				case 206:
				case 416:
				default:
					*state_code = CURL_HTTP_OTHER;
					break;
            };
		} else {
            ret = 0;
        }

        if (curl){
			curl_easy_cleanup(curl);
		}
	}

	return ret;
}