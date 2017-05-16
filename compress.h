#ifndef _COMPRESS_H_
#define _COMPRESS_H_
                     
int  compress(unsigned char *dest, size_t *destLen, const unsigned char *source, size_t sourceLen);

int  uncompress(unsigned char *dest, size_t *destLen, const unsigned char *source, size_t sourceLen);

size_t compressBound(size_t sourceLen);

#endif
