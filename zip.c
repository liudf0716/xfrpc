
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
	if (!source || len < 0 || !dest || !wlen)
		return Z_STREAM_ERROR;

	z_stream strm = {
		.zalloc = Z_NULL,
		.zfree = Z_NULL,
		.opaque = Z_NULL,
		.avail_in = (uInt)len,
		.next_in = source
	};
	unsigned char out[CHUNK] = {0};
	int totalsize = 0;
	uint8_t *buf = NULL;

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

		if (ret == Z_STREAM_ERROR || ret == Z_NEED_DICT ||
		    (ret < 0 && ret != Z_BUF_ERROR)) {
			free(buf);
			deflateEnd(&strm);
			return (ret == Z_NEED_DICT) ? Z_DATA_ERROR : ret;
		}

		have = CHUNK - strm.avail_out;
		if (have > 0) {
			uint8_t *nb = realloc(buf, (size_t)totalsize + have);
			if (!nb) {
				free(buf);
				deflateEnd(&strm);
				return Z_MEM_ERROR;
			}
			buf = nb;
			memcpy(buf + totalsize, out, have);
			totalsize += (int)have;
		}
	} while (strm.avail_out == 0);

	/* Clean up and set output length */
	deflateEnd(&strm);
	if (ret != Z_STREAM_END) {
		free(buf);
		return Z_DATA_ERROR;
	}
	*dest = buf;
	*wlen = totalsize;
	return Z_OK;
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
	if (!source || len < 0 || !dest || !rlen)
		return Z_STREAM_ERROR;

	z_stream strm = {
		.zalloc = Z_NULL,
		.zfree = Z_NULL,
		.opaque = Z_NULL,
		.avail_in = (uInt)len,
		.next_in = source
	};  
	unsigned char out[CHUNK] = {0};  
	int totalsize = 0;  
	uint8_t *buf = NULL;

	/* Initialize inflate: match deflate_write's windowBits | GZIP_ENCODING */
	ret = gzip ? inflateInit2(&strm, windowBits | GZIP_ENCODING) : inflateInit(&strm);
	if (ret != Z_OK)  
		return ret;  

	/* Decompress until deflate stream ends */
	do {  
		strm.avail_out = CHUNK;  
		strm.next_out = out;  
		ret = inflate(&strm, Z_NO_FLUSH);   

		if (ret == Z_NEED_DICT || (ret < 0 && ret != Z_BUF_ERROR)) {
			free(buf);
			inflateEnd(&strm);  
			return (ret == Z_NEED_DICT) ? Z_DATA_ERROR : ret;
		}

		have = CHUNK - strm.avail_out;  
		if (have > 0) {
			uint8_t *nb = realloc(buf, (size_t)totalsize + have);
			if (!nb) {
				free(buf);
				inflateEnd(&strm);
				return Z_MEM_ERROR;
			}
			buf = nb;
			memcpy(buf + totalsize, out, have);  
			totalsize += (int)have;  
		}
	} while (strm.avail_out == 0);  

	/* Clean up and set output length */
	inflateEnd(&strm);  
	if (ret != Z_STREAM_END) {
		free(buf);
		return Z_DATA_ERROR;
	}
	*dest = buf;
	*rlen = totalsize;
	return Z_OK;  
}
