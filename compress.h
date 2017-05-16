#ifndef _COMPRESS_H_
#define _COMPRESS_H_

struct evbuffer;

int compress2(unsigned char *dest, size_t *destLen, const unsigned char *source,
                        size_t sourceLen, int level);
                        

int  compress(unsigned char *dest, size_t *destLen, const unsigned char *source, size_t sourceLen);

size_t compressBound(size_t sourceLen);

#endif
