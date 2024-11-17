
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#include <string.h>
#include <stdlib.h>
#include <zlib.h>

#include "zip.h"

/**
 * @brief Compress data using zlib/gzip deflate
 * 
 * @param source Input data buffer to compress
 * @param len Length of input data
 * @param dest Pointer to output buffer pointer (will be allocated)
 * @param wlen Pointer to store compressed data length
 * @param gzip 1 for gzip format, 0 for raw deflate
 * @return int Z_OK on success, or zlib error code
 */
int deflate_write(uint8_t *source, int len, uint8_t **dest, int *wlen, int gzip)
{
	int ret;
	unsigned have;
	z_stream strm = {
		.zalloc = Z_NULL,
		.zfree = Z_NULL,
		.opaque = Z_NULL,
		.avail_in = len,
		.next_in = source
	};
	unsigned char out[CHUNK] = {0};
	int totalsize = 0;

	/* Initialize deflate */
	if (gzip) {
		ret = deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
						  windowBits | GZIP_ENCODING, 8, Z_DEFAULT_STRATEGY);
	} else {
		ret = deflateInit(&strm, Z_DEFAULT_COMPRESSION);
	}

	if (ret != Z_OK)
		return ret;

	/* Compress until end of data */
	do {
		strm.avail_out = CHUNK;
		strm.next_out = out;
		ret = deflate(&strm, Z_FINISH);

		if (ret < 0 && ret != Z_STREAM_END) {
			deflateEnd(&strm);
			return (ret == Z_NEED_DICT) ? Z_DATA_ERROR : ret;
		}

		have = CHUNK - strm.avail_out;
		totalsize += have;
		*dest = realloc(*dest, totalsize);
		memcpy(*dest + totalsize - have, out, have);
	} while (strm.avail_out == 0);

	/* Clean up and set output length */
	deflateEnd(&strm);
	*wlen = totalsize;
	return ret == Z_STREAM_END ? Z_OK : Z_DATA_ERROR;
}

/**
 * @brief Decompress data using zlib/gzip inflate
 * 
 * @param source Input compressed data buffer
 * @param len Length of input data
 * @param dest Pointer to output buffer pointer (will be allocated)
 * @param rlen Pointer to store output length
 * @param gzip 1 for gzip format, 0 for raw deflate
 * @return int Z_OK on success, or zlib error code
 */
int inflate_read(uint8_t *source, int len, uint8_t **dest, int *rlen, int gzip)
{  
	int ret;  
	unsigned have;  
	z_stream strm = {
		.zalloc = Z_NULL,
		.zfree = Z_NULL,
		.opaque = Z_NULL,
		.avail_in = len,
		.next_in = source
	};  
	unsigned char out[CHUNK] = {0};  
	int totalsize = 0;  

	/* Initialize inflate */
	ret = gzip ? inflateInit2(&strm, -MAX_WBITS) : inflateInit(&strm);
	if (ret != Z_OK)  
		return ret;  

	/* Decompress until deflate stream ends */
	do {  
		strm.avail_out = CHUNK;  
		strm.next_out = out;  
		ret = inflate(&strm, Z_NO_FLUSH);   

		if (ret < 0) {
			inflateEnd(&strm);  
			return (ret == Z_NEED_DICT) ? Z_DATA_ERROR : ret;
		}

		have = CHUNK - strm.avail_out;  
		totalsize += have;  
		*dest = realloc(*dest, totalsize);  
		memcpy(*dest + totalsize - have, out, have);  
	} while (strm.avail_out == 0);  

	/* Clean up and set output length */
	inflateEnd(&strm);  
	*rlen = totalsize;
	return ret == Z_STREAM_END ? Z_OK : Z_DATA_ERROR;  
}
