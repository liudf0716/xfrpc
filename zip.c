/* vim: set et ts=4 sts=4 sw=4 : */
/********************************************************************\
 * This program is free software; you can redistribute it and/or    *
 * modify it under the terms of the GNU General Public License as   *
 * published by the Free Software Foundation; either version 2 of   *
 * the License, or (at your option) any later version.              *
 *                                                                  *
 * This program is distributed in the hope that it will be useful,  *
 * but WITHOUT ANY WARRANTY; without even the implied warranty of   *
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the    *
 * GNU General Public License for more details.                     *
 *                                                                  *
 * You should have received a copy of the GNU General Public License*
 * along with this program; if not, contact:                        *
 *                                                                  *
 * Free Software Foundation           Voice:  +1-617-542-5942       *
 * 59 Temple Place - Suite 330        Fax:    +1-617-542-2652       *
 * Boston, MA  02111-1307,  USA       gnu@gnu.org                   *
 *                                                                  *
\********************************************************************/

/** @file zip.c
    @brief zlib related function
    @author Copyright (C) 2016 Dengfeng Liu <liu_df@qq.com>
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
