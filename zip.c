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
    @author Copyright (C) 2016 Dengfeng Liu <liudengfeng@kunteng.org>
*/

#include <string.h>
#include <stdlib.h>
#include <zlib.h>

#include "zip.h"

int
deflate_write(uint8 *source, int len, uint8 **dest, int *wlen, int gzip)
{
	int ret;  
	unsigned have;  
	z_stream strm;  
	unsigned char out[CHUNK] = {0};  
	int totalsize = 0;  

	/* allocate inflate state */  
	strm.zalloc = Z_NULL;  
	strm.zfree = Z_NULL;  
	strm.opaque = Z_NULL;  
	strm.avail_in = 0;  
	strm.next_in = Z_NULL;  

	if(gzip)  
		ret = deflateInit2(&strm, Z_DEFAULT_COMPRESSION, Z_DEFLATED,
					  windowBits | GZIP_ENCODING,
					  8,
					  Z_DEFAULT_STRATEGY);  
	else  
		ret = deflateInit(&strm, Z_DEFAULT_COMPRESSION);  
	
	if (ret != Z_OK)  
		return ret;  

	strm.avail_in = len;  
	strm.next_in = source;  
  
	do {  
		strm.avail_out = CHUNK;  
		strm.next_out = out;  
		ret = deflate(&strm, Z_FINISH);
		switch (ret) {  
		case Z_NEED_DICT:  
			ret = Z_DATA_ERROR; /* and fall through */  
		case Z_DATA_ERROR:  
		case Z_MEM_ERROR:  
			deflateEnd(&strm);  
			return ret;  
		}  

		have = CHUNK - strm.avail_out;  
		totalsize += have;  
		*dest = realloc(*dest, totalsize);  
		memcpy(*dest + totalsize - have, out, have);
	} while (strm.avail_out == 0);  

	/* clean up and return */  
	(void)deflateEnd(&strm);
	*wlen = totalsize;
	return ret == Z_STREAM_END ? Z_OK : Z_DATA_ERROR;
}

int 
inflate_read(uint8 *source, int len, uint8 **dest, int *rlen, int gzip)
{  
	int ret;  
	unsigned have;  
	z_stream strm;  
	unsigned char out[CHUNK] = {0};  
	int totalsize = 0;  

	/* allocate inflate state */  
	strm.zalloc = Z_NULL;  
	strm.zfree = Z_NULL;  
	strm.opaque = Z_NULL;  
	strm.avail_in = 0;  
	strm.next_in = Z_NULL;  

	if(gzip)  
		ret = inflateInit2(&strm, -MAX_WBITS);  
	else  
		ret = inflateInit(&strm);  

	if (ret != Z_OK)  
		return ret;  

	strm.avail_in = len;  
	strm.next_in = source;  

	/* run inflate() on input until output buffer not full */  
	do {  
		strm.avail_out = CHUNK;  
		strm.next_out = out;  
		ret = inflate(&strm, Z_NO_FLUSH);   
		switch (ret) {  
		case Z_NEED_DICT:  
			ret = Z_DATA_ERROR; /* and fall through */  
		case Z_DATA_ERROR:  
		case Z_MEM_ERROR:  
			inflateEnd(&strm);  
			return ret;  
		}  
		have = CHUNK - strm.avail_out;  
		totalsize += have;  
		*dest = realloc(*dest, totalsize);  
		memcpy(*dest + totalsize - have, out, have);  
	} while (strm.avail_out == 0);  

	/* clean up and return */  
	(void)inflateEnd(&strm);  
	*rlen = totalsize;
	return ret == Z_STREAM_END ? Z_OK : Z_DATA_ERROR;  
}

