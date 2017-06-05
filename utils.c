#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <errno.h>

#include "utils.h"

// s_sleep using select instead of sleep
// s: second, u: usec 10^6usec = 1s
void s_sleep(unsigned int s, unsigned int u)
{
	struct timeval timeout;

	timeout.tv_sec = s;
	timeout.tv_usec = u;
	select(0, NULL, NULL, NULL, &timeout);
}
