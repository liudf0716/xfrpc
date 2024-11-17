
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef XFRPC_ZIP_H
#define XFRPC_ZIP_H

#define CHUNK   16384  
#define windowBits 		15
#define GZIP_ENCODING 	16

#include <stdint.h>

int deflate_write(uint8_t *source, int len, uint8_t **dest, int *wlen, int gzip);

int inflate_read(uint8_t *source, int len, uint8_t **dest, int *rlen, int gzip);

#endif
