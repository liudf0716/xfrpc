#ifndef _UTILS_H_
#define _UTILS_H_

/* curl define */
// curl methods 
#define HTTP_GET 0
#define HTTP_POST 1

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
	char 	*ptr;
	size_t 	len;
};

void s_sleep(unsigned int s, unsigned int u);

// is_valid_ip_address:
// return 0:ipaddress unlegal
int is_valid_ip_address(const char *ip_address);
int show_net_ifname();
int get_net_ifname(char *if_buf, int blen);
int get_net_mac(char *net_if_name, char *mac, int mac_len);
int dns_unified(const char *dname, char *udname_buf, int udname_buf_len);

struct mycurl_string *mycurl_string_init(struct mycurl_string *stream);
int net_visit(const char *url, 
			struct mycurl_string *s,
			int method,
			char *post_buf,
			long timeout, 
			int *state_code,
			double *down_size);
void mycurl_string_free(struct mycurl_string *stream);

#endif //_UTILS_H_
