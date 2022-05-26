
#include "common.h"
#include "tcpmux.h"
#include "client.h"
#include "config.h"
#include "debug.h"
#include "control.h"

static uint8_t proto_version = 0;

static struct tcp_mux_type_desc type_desc[] = {
	{DATA, "data"},
	{WINDOW_UPDATE, "window update"},
	{PING, "ping"},
	{GO_AWAY, "go away"},
};

static struct tcp_mux_flag_desc flag_desc[] = {
	{ZERO, "zero"},
	{SYN, "syn"},
	{ACK, "ack"},
	{FIN, "fin"},
	{RST, "rst"},
};

static const char *
type_2_desc(enum tcp_mux_type type)
{
	for(int i = 0; i < sizeof(type_desc)/sizeof(struct tcp_mux_type_desc); i++){
		if (type == type_desc[i].type)
			return type_desc[i].desc;
	}

	return "unkown_type";
}

static const char *
flag_2_desc(enum tcp_mux_flag flag)
{
	for(int i = 0; i < sizeof(flag_desc)/sizeof(struct tcp_mux_flag_desc); i++){
		if (flag == flag_desc[i].flag)
			return flag_desc[i].desc;
	}

	return "unknown_flag";
}

static int
valid_tcp_mux_type(uint8_t type)
{
	if (type >= DATA && type <= GO_AWAY)
		return 1;

	return 0;
}

static int
valid_tcp_mux_flag(uint16_t flag)
{
	if (flag >= ZERO && flag <= RST)
		return 1;

	return 0;
}

static int
valid_tcp_mux_sid(uint32_t sid)
{
	if (sid == 1)
		return 1;
	
	return get_proxy_client(sid)?1:0;
}


void 
tcp_mux_encode(enum tcp_mux_type type, enum tcp_mux_flag flags, uint32_t stream_id, uint32_t length, struct tcp_mux_header *tmux_hdr)
{
	assert(tmux_hdr);
	tmux_hdr->version 	= proto_version;
	tmux_hdr->type		= type;
	tmux_hdr->flags		= htons(flags);
	tmux_hdr->stream_id	= htonl(stream_id);
	tmux_hdr->length	= length?htonl(length):0;
}

static uint32_t
tcp_mux_flag()
{	
	struct common_conf 	*c_conf = get_common_config();
	return c_conf->tcp_mux;
}

static void
dump_tcp_mux_header(uint8_t *data, int len)
{
	if (len != 12)
		return;

	printf("tcp mux header is : \n");
	for (int i = 0; i < len; i++)
		printf("%2x", data[i]);
	printf("\n");
}

static uint32_t
parse_tcp_mux_proto(uint8_t *data, int len, uint32_t *flag, uint32_t *type, uint32_t *stream_id, uint32_t *dlen)
{
	struct common_conf *c_conf = get_common_config();
	if (!c_conf->tcp_mux)
		return 0;	

	if (len < sizeof(struct tcp_mux_header))
		return 0;

	struct tcp_mux_header *hdr = (struct tcp_mux_header *)data;
	if(hdr->version == proto_version && 
	   valid_tcp_mux_type(hdr->type) && 
	   valid_tcp_mux_flag(htons(hdr->flags))) {
		if (hdr->type == DATA && !valid_tcp_mux_sid(htonl(hdr->stream_id))) {
			debug(LOG_INFO, "!!!!!type is DATA but cant find stream_id : type [%s] flag [%s] stream_id[%d]", 
				type_2_desc(hdr->type), flag_2_desc(htons(hdr->flags)), htonl(hdr->stream_id));
			dump_tcp_mux_header(data, len);
			exit(-1);
		}
		*type = hdr->type;
		*flag = htons(hdr->flags);
		*stream_id = htonl(hdr->stream_id);
		*dlen = htonl(hdr->length);
		return 1;
	}

	return 0;
}

uint32_t 
get_next_session_id() {
	static uint32_t next_session_id = 1;
	uint32_t id = next_session_id;
	next_session_id += 2;
	return id;
}

void
tcp_mux_send_win_update_syn(struct bufferevent *bout, uint32_t stream_id)
{
	if (!tcp_mux_flag()) return;

	struct tcp_mux_header tmux_hdr;
	memset(&tmux_hdr, 0, sizeof(tmux_hdr));
	tcp_mux_encode(WINDOW_UPDATE, SYN, stream_id, 0, &tmux_hdr);
	debug(LOG_DEBUG, "tcp mux [%d] send wind update syn", stream_id);
	bufferevent_write(bout, (uint8_t *)&tmux_hdr, sizeof(tmux_hdr));
}

void
tcp_mux_send_win_update_ack(struct bufferevent *bout, uint32_t stream_id, uint32_t delta)
{
	if (!tcp_mux_flag()) return;

	struct tcp_mux_header tmux_hdr;
	memset(&tmux_hdr, 0, sizeof(tmux_hdr));
	tcp_mux_encode(WINDOW_UPDATE, ZERO, stream_id, delta, &tmux_hdr);
	debug(LOG_DEBUG, "tcp mux [%d] send wind update ZERO [%d]", stream_id, delta);
	bufferevent_write(bout, (uint8_t *)&tmux_hdr, sizeof(tmux_hdr));
}

void
tcp_mux_send_win_update_rst(struct bufferevent *bout, uint32_t stream_id)
{
	if (!tcp_mux_flag()) return;

	struct tcp_mux_header tmux_hdr;
	memset(&tmux_hdr, 0, sizeof(tmux_hdr));
	tcp_mux_encode(WINDOW_UPDATE, RST, stream_id, 0, &tmux_hdr);
	debug(LOG_DEBUG, "tcp mux [%d] send wind update RST", stream_id);
	bufferevent_write(bout, (uint8_t *)&tmux_hdr, sizeof(tmux_hdr));
}

void
tcp_mux_send_data(struct bufferevent *bout, uint32_t stream_id, uint32_t length)
{
	if (!tcp_mux_flag()) return;

	struct tcp_mux_header tmux_hdr;
	memset(&tmux_hdr, 0, sizeof(tmux_hdr));
	tcp_mux_encode(DATA, ZERO, stream_id, length, &tmux_hdr);
	debug(LOG_DEBUG, "tcp mux [%d] send data len : %d", stream_id, length);
	bufferevent_write(bout, (uint8_t *)&tmux_hdr, sizeof(tmux_hdr));
}

void 
tcp_mux_send_ping(struct bufferevent *bout, uint32_t ping_id)
{
	if (!tcp_mux_flag()) return;

	struct tcp_mux_header tmux_hdr;
	memset(&tmux_hdr, 0, sizeof(tmux_hdr));
	tcp_mux_encode(PING, SYN, 0, ping_id, &tmux_hdr);
	//debug(LOG_DEBUG, "tcp mux send ping syn : %d", ping_id);
	bufferevent_write(bout, (uint8_t *)&tmux_hdr, sizeof(tmux_hdr));
}

static void 
tcp_mux_handle_ping(struct bufferevent *bout, uint32_t ping_id)
{
	if (!tcp_mux_flag()) return;

	struct tcp_mux_header tmux_hdr;
	memset(&tmux_hdr, 0, sizeof(tmux_hdr));
	tcp_mux_encode(PING, ACK, 0, ping_id, &tmux_hdr);
	//debug(LOG_DEBUG, "tcp mux send ping ack : %d", ping_id);
	bufferevent_write(bout, (uint8_t *)&tmux_hdr, sizeof(tmux_hdr));
}

void 
handle_tcp_mux_frps_msg(uint8_t *buf, int ilen, void (*fn)(uint8_t *, int, void *))
{
	static uint32_t l_stream_id = 0;
	static uint32_t l_dlen = 0;
	static uint32_t l_type = 0;
	static uint32_t l_flag = 0;
	uint8_t *data = buf;
	while (ilen > 0) {
		uint32_t type = 0, stream_id = 0, dlen = 0, flag = 0;
		uint32_t is_tmux = parse_tcp_mux_proto(data, ilen, &flag, &type, &stream_id, &dlen); 
		if (is_tmux) {
			debug(LOG_DEBUG, "receive tcp mux type [%s] flag [%s] stream_id [%d] dlen [%d] ilen [%d]", 
							type_2_desc(type), flag_2_desc(flag), stream_id, dlen, ilen);
			data += sizeof(struct tcp_mux_header);
			ilen -= sizeof(struct tcp_mux_header);
			assert(ilen >= 0);
			l_stream_id = stream_id;
			l_type = type;
			l_flag = flag;
			l_dlen = dlen;
		} else {
			struct proxy_client *pc = get_proxy_client(l_stream_id);
			debug(LOG_DEBUG, "receive only %s data : l_stream_id %d l_type %s l_flag %s l_dlen %d ilen %d", 
							!pc?"main control ":"worker ", 
							l_stream_id, type_2_desc(l_type), 
							flag_2_desc(l_flag), l_dlen, ilen);
			assert(ilen);
			if (!pc || (pc && !pc->local_proxy_bev)) {
				assert(ilen >= l_dlen);
				fn(data, l_dlen, pc);
				data += l_dlen;
				ilen -= l_dlen;
			} else if ( ilen >= l_dlen) {
				assert(pc->local_proxy_bev);
				bufferevent_write(pc->local_proxy_bev, data, l_dlen);
				data += l_dlen;
				ilen -= l_dlen;
				l_dlen = 0;
			} else {
				bufferevent_write(pc->local_proxy_bev, data, ilen);
				l_dlen -= ilen;
				ilen 	= 0;
			}

			continue;
		}

		struct proxy_client *pc = get_proxy_client(stream_id);
		if (type == DATA) {
			debug(LOG_DEBUG, 
				"receive data frps dlen %d ilen %d stream_id %d", 
				dlen, ilen, stream_id);
			if (ilen == 0) {
				continue;
			}

			if (!pc || (pc && !pc->local_proxy_bev)) {
				debug(LOG_DEBUG, "receive control msg");
				assert(ilen >= dlen);
				fn(data, dlen, pc);
				data += dlen;
				ilen -= dlen;
			} else if ( ilen >= dlen){
				debug(LOG_DEBUG, "receive proxy worker data and forword: ilen %d dlen %d", ilen, dlen);
				bufferevent_write(pc->local_proxy_bev, data, dlen);
				data += dlen;
				ilen -= dlen;
				l_dlen = 0;
			} else {
				debug(LOG_DEBUG, "receive proxy worker data partially : ilen %d dlen %d", ilen, dlen);
				bufferevent_write(pc->local_proxy_bev, data, ilen);
				l_dlen -= ilen;
				ilen 	= 0;
			}
		} else if (type == PING) {
			struct bufferevent *bout = get_main_control()->connect_bev;
			assert(bout);
			if (flag == SYN)
				tcp_mux_handle_ping(bout, dlen);
		} else if (type == WINDOW_UPDATE ) {
			if (flag == RST) {
				debug(LOG_DEBUG, "receive tcp mux window_update flag %s ", flag_2_desc(flag));
				del_proxy_client(pc);	
			} else if (pc){
				if (dlen > 0) {
					debug(LOG_DEBUG, "receive tcp mux window_update flag %s increase send_window %d", flag_2_desc(flag), dlen);
					pc->send_window += dlen;
					bufferevent_enable(pc->local_proxy_bev, EV_READ|EV_WRITE);
				}
			}
		} else {
			debug(LOG_INFO, "no need unhandle tcp mux msg : type %s flag %s stream_id %d dlen %d ilen %d", 
							type_2_desc(type), flag_2_desc(flag),  stream_id, dlen, ilen);
		}
	}
}
