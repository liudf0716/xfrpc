#ifndef _ZIP_H_
#define _ZIP_H_

#define CHUNK   16384  
#define windowBits 		15
#define GZIP_ENCODING 	16

int deflate_write(char *source, int len, char **dest, int *wlen, int gzip);

int inflate_read(char *source, int len, char **dest, int *rlen, int gzip);

#endif
