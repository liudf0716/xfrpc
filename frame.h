#ifndef	_FRAME_H_
#define	_FRAME_H_

#include <stdlib.h>
#include <stdio.h>

#include "uthash.h"
#include "common.h"

#define VERI 0
#define CMDI 1
#define LENI 2
#define SIDI 4
#define DATAI 8

// cmds
enum cmd_type {
	cmdSYN  = 0, 		// stream open
	cmdFIN,             // stream close, a.k.a EOF mark
	cmdPSH,             // data push
	cmdNOP,             // no operation
};

struct frame {
	char ver;
	char cmd;
	ushort len;
	uint32_t sid;
	unsigned char *data;
};

struct frame *new_frame(char cmd, uint32_t sid);
int get_header_size();
struct frame *raw_frame(unsigned char *buf, const size_t buf_len);
struct frame *raw_frame_only_msg(unsigned char *buf, const size_t buf_len);
void set_frame_cmd(struct frame *f, char cmd);
void set_frame_len(struct frame *f, ushort data_len);
void free_frame(struct frame *f);

#endif //_FRAME_H_