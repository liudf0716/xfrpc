#include "frame.h"

const static int  	size_of_ver = 1;
const static int  	size_of_cmd = 1;
const static int  	size_of_length = 2;
const static int  	size_of_sid = 4;
const static char 	version = 1;

int get_header_size() {
	return size_of_ver + size_of_cmd + size_of_length + size_of_sid;
}

struct frame *new_frame(char cmd, uint32_t sid) {
	struct frame *f = calloc(sizeof(struct frame), 1);
	if (f != NULL) {
		f->ver = version;
		f->cmd = cmd;
		f->sid = sid;
		f->len = 0;
	}

	return f;
}

struct frame *raw_frame(char *buf, const size_t buf_len) {
	int header_size = get_header_size();
	if (buf_len < header_size) {
		return NULL;
	}
	char ver = buf[VERI];
	char cmd = buf[CMDI];
	uint32_t sid = *(uint32_t *)(buf + SIDI);

	struct frame *f = new_frame(cmd, sid);
	f->ver = ver;
	f->len = *(ushort *)(buf + LENI);
	f->data = buf_len > header_size ? buf + header_size : NULL;

	return f;
}

void free_frame(struct frame *f) {
	if (f) {
		free(f);
	}
}