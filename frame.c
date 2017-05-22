#include "frame.h"

const static int  size_of_ver = 1;
const static int  size_of_cmd = 1;
const static int  size_of_length = 2;
const static int  size_of_sid = 4;

const static char version = 1; 

int get_header_size() {
	return size_of_ver + size_of_cmd + size_of_length + size_of_sid;
}

struct frame *new_frame(char cmd, uint32_t sid) {
	struct frame *f = calloc(sizeof(struct frame), 1);
	if (f != NULL) {
		f->cmd = cmd;
		f->sid = sid;
		f->ver = version;
	}

	return f;
}

void free_frame(struct frame *f) {
	if (f) {
		free(f);
	}
}