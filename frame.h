#ifndef	_FRAME_H_
#define	_FRAME_H_

#include <stdlib.h>
#include <stdio.h>

#include "uthash.h"

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
	uint32_t sid;
	char *data;
};

// const (
// 	sizeOfVer    = 1
// 	sizeOfCmd    = 1
// 	sizeOfLength = 2
// 	sizeOfSid    = 4
// 	headerSize   = sizeOfVer + sizeOfCmd + sizeOfSid + sizeOfLength
// )
struct frame *new_frame(char cmd, uint32_t sid);
int get_header_size();

#endif //_FRAME_H_