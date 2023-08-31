#ifndef _TELNETD_H
#define _TELNETD_H

#define BUFSIZE 4000
#define SOCKET_TYPE AF_INET
#define MIN(X, Y) ((X) < (Y) ? (X) : (Y))
enum
{
	GETPTY_BUFSIZE = 16
};

int  simple_telnetd_start(uint16_t port);

#endif