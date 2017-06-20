#ifndef _COMMON_H_
#define _COMMON_H_

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>

#include "uthash.h"

// #define BIGENDIAN_64BIT 0
#define BIGENDIAN_32BIT 1

#define SAFE_FREE(m) 	\
if (m) free(m)

uint64_t ntoh64(const uint64_t input);
uint64_t hton64(const uint64_t input);

#ifdef BIGENDIAN_64BIT
	typedef uint64_t msg_size_t;
	#define msg_ntoh(l)		\
	ntoh64(l)

	#define msg_hton(b) 	\
	hton64(b)

#elif BIGENDIAN_32BIT
	#define msg_ntoh(l)		\
	ntohl(l)

	#define msg_hton(b)		\
	htonl(b)

	typedef uint32_t msg_size_t;
#endif //BIGENDIAN_64BIT

#endif //_COMMON_H_