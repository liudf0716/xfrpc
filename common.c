
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#include "uthash.h"
#include "common.h"

uint64_t ntoh64(const uint64_t input)
{
#if __BYTE_ORDER == __BIG_ENDIAN
    return input;
#else
    return ((uint64_t)ntohl(input & 0xFFFFFFFF) << 32) | 
           ntohl((input >> 32) & 0xFFFFFFFF);
#endif
}

uint64_t hton64(const uint64_t input)
{
#if __BYTE_ORDER == __BIG_ENDIAN
    return input;
#else
    return ((uint64_t)htonl(input & 0xFFFFFFFF) << 32) | 
           htonl((input >> 32) & 0xFFFFFFFF);
#endif
}
