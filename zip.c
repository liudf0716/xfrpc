

#include <zlib.h>

#include "compress.h"

int
deflate_write(char *source, int len, char **dest, int *wlen, int gzip)
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
inflate_read(char *source, int len, char **dest, int *rlen, int gzip)
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

