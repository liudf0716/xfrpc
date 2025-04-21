/*
 * Simple telnet server
 * Bjorn Wesen, Axis Communications AB (bjornw@axis.com)
 *
 * This file is distributed under the GNU Public License (GPL),
 * please see the file LICENSE for further information.
 *
 * ---------------------------------------------------------------------------
 * (C) Copyright 2000, Axis Communications AB, LUND, SWEDEN
 ****************************************************************************
 *
 * The telnetd manpage says it all:
 *
 *   Telnetd operates by allocating a pseudo-terminal device (see pty(4))  for
 *   a client, then creating a login process which has the slave side of the
 *   pseudo-terminal as stdin, stdout, and stderr. Telnetd manipulates the
 *   master side of the pseudo-terminal, implementing the telnet protocol and
 *   passing characters between the remote client and the login process.
 *
 * Vladimir Oleynik <dzo@simtreas.ru> 2001
 *     Set process group corrections, initial busybox port
 *
 * BusyBox is distributed under version 2 of the General Public License please
 * see the file LICENSE for further information. Version 2 is the only version
 * of this license which this version of BusyBox
 * (or modified versions derived from this one) may be
 * distributed under.
 * https://busybox.net/downloads/busybox-0.60.5.tar.bz2
 */

#include <sys/time.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <stdio.h>
#include <signal.h>
#include <termios.h>
#include <arpa/telnet.h>
#include <ctype.h>
#include <sys/syslog.h>
#include <pthread.h>

#include "telnetd.h"
#include "../debug.h"


typedef struct sockaddr_in sockaddr_type;
static const char *loginpath = "/bin/login";

/* shell name and arguments */

static const char *argv_init[] = {NULL, NULL};

/* structure that describes a session */

struct tsession
{
	struct tsession *next;
	int sockfd, ptyfd;
	int shell_pid;
	/* two circular buffers */
	char *buf1, *buf2;
	int rdidx1, wridx1, size1;
	int rdidx2, wridx2, size2;
};

/*

   This is how the buffers are used. The arrows indicate the movement
   of data.

   +-------+     wridx1++     +------+     rdidx1++     +----------+
   |       | <--------------  | buf1 | <--------------  |          |
   |       |     size1--      +------+     size1++      |          |
   |  pty  |                                            |  socket  |
   |       |     rdidx2++     +------+     wridx2++     |          |
   |       |  --------------> | buf2 |  --------------> |          |
   +-------+     size2++      +------+     size2--      +----------+

   Each session has got two buffers.

*/

static int maxfd;
static struct tsession *sessions;

/*

   Remove all IAC's from the buffer pointed to by bf (recieved IACs are ignored
   and must be removed so as to not be interpreted by the terminal).  Make an
   uninterrupted string of characters fit for the terminal.  Do this by packing
   all characters meant for the terminal sequentially towards the end of bf.

   Return a pointer to the beginning of the characters meant for the terminal.
   and make *num_totty the number of characters that should be sent to
   the terminal.

   Note - If an IAC (3 byte quantity) starts before (bf + len) but extends
   past (bf + len) then that IAC will be left unprocessed and *processed will be
   less than len.

   FIXME - if we mean to send 0xFF to the terminal then it will be escaped,
   what is the escape character?  We aren't handling that situation here.

   CR-LF ->'s CR mapping is also done here, for convenience

  */
static char *
remove_iacs(struct tsession *ts, int *pnum_totty)
{
	unsigned char *ptr0 = (unsigned char *)(ts->buf1 + ts->wridx1);
	unsigned char *ptr = ptr0;
	unsigned char *totty = ptr;
	unsigned char *end = ptr + MIN(BUFSIZE - ts->wridx1, ts->size1);
	int processed;
	int num_totty;

	while (ptr < end)
	{
		if (*ptr != IAC)
		{
			int c = *ptr;
			*totty++ = *ptr++;
			/* We now map \r\n ==> \r for pragmatic reasons.
			 * Many client implementations send \r\n when
			 * the user hits the CarriageReturn key.
			 */
			if (c == '\r' && (*ptr == '\n' || *ptr == 0) && ptr < end)
				ptr++;
		}
		else
		{
			/*
			 * TELOPT_NAWS support!
			 */
			if ((ptr + 2) >= end)
			{
				/* only the beginning of the IAC is in the
				buffer we were asked to process, we can't
				process this char. */
				break;
			}

			/*
			 * IAC -> SB -> TELOPT_NAWS -> 4-byte -> IAC -> SE
			 */
			else if (ptr[1] == SB && ptr[2] == TELOPT_NAWS)
			{
				struct winsize ws;
				if ((ptr + 8) >= end)
					break; /* incomplete, can't process */
				ws.ws_col = (ptr[3] << 8) | ptr[4];
				ws.ws_row = (ptr[5] << 8) | ptr[6];
				(void)ioctl(ts->ptyfd, TIOCSWINSZ, (char *)&ws);
				ptr += 9;
			}
			else
			{
				/* skip 3-byte IAC non-SB cmd */
				ptr += 3;
			}
		}
	}

	processed = ptr - ptr0;
	num_totty = totty - ptr0;
	/* the difference between processed and num_to tty
	   is all the iacs we removed from the stream.
	   Adjust buf1 accordingly. */
	ts->wridx1 += processed - num_totty;
	ts->size1 -= processed - num_totty;
	*pnum_totty = num_totty;
	/* move the chars meant for the terminal towards the end of the
	buffer. */
	return memmove(ptr - num_totty, ptr0, num_totty);
}

static int 
getpty(char *line)
{
#ifdef OLD_GETPTY
	int p;
	p = open("/dev/ptmx", 2);
	if (p > 0)
	{
		grantpt(p);
		unlockpt(p);
		strcpy(line, ptsname(p));
		return (p);
	}
	return -1;
#else

	int p;
	p = open("/dev/ptmx", O_RDWR);
	if (p >= 0)
	{
		grantpt(p);
		unlockpt(p);
		if (ptsname_r(p, line, GETPTY_BUFSIZE - 1) != 0)
		{
			debug(LOG_ERR, "ptsname error (is /dev/pts mounted?)");
			return -1;
		}
		line[GETPTY_BUFSIZE - 1] = '\0';
		return p;
	}
	struct stat stb;
	int i;
	int j;

	strcpy(line, "/dev/ptyXX");

	for (i = 0; i < 16; i++)
	{
		line[8] = "pqrstuvwxyzabcde"[i];
		line[9] = '0';
		if (stat(line, &stb) < 0)
		{
			continue;
		}
		for (j = 0; j < 16; j++)
		{
			line[9] = j < 10 ? j + '0' : j - 10 + 'a';
			p = open(line, O_RDWR | O_NOCTTY);
			if (p >= 0)
			{
				line[5] = 't';
				return p;
			}
		}
	}
	return -1;
#endif
}

static void 
send_iac(struct tsession *ts, unsigned char command, int option)
{
	/* We rely on that there is space in the buffer for now.  */
	char *b = ts->buf2 + ts->rdidx2;
	*b++ = IAC;
	*b++ = command;
	*b++ = option;
	ts->rdidx2 += 3;
	ts->size2 += 3;
}

static struct tsession *
make_new_session(int sockfd)
{
	struct termios termbuf;
	int pty, pid;
	char tty_name[32];
	struct tsession *ts = malloc(sizeof(struct tsession) + BUFSIZE * 2);

	ts->buf1 = (char *)(&ts[1]);
	ts->buf2 = ts->buf1 + BUFSIZE;
	ts->sockfd = sockfd;

	ts->rdidx1 = ts->wridx1 = ts->size1 = 0;
	ts->rdidx2 = ts->wridx2 = ts->size2 = 0;

	/* Got a new connection, set up a tty and spawn a shell.  */

	pty = getpty(tty_name);

	if (pty < 0)
	{
		debug(LOG_ERR, "All network ports in use!");
		return 0;
	}

	if (pty > maxfd)
		maxfd = pty;

	ts->ptyfd = pty;

	/* Make the telnet client understand we will echo characters so it
	 * should not do it locally. We don't tell the client to run linemode,
	 * because we want to handle line editing and tab completion and other
	 * stuff that requires char-by-char support.
	 */

	send_iac(ts, DO, TELOPT_ECHO);
	send_iac(ts, DO, TELOPT_NAWS);
	send_iac(ts, DO, TELOPT_LFLOW);
	send_iac(ts, WILL, TELOPT_ECHO);
	send_iac(ts, WILL, TELOPT_SGA);

	if ((pid = fork()) < 0)
	{
		syslog(LOG_ERR, "Can`t forking");
	}
	if (pid == 0)
	{
		/* In child, open the child's side of the tty.  */
		int i;

		for (i = 0; i <= maxfd; i++)
			close(i);
		/* make new process group */
		setsid();

		if (open(tty_name, O_RDWR) < 0)
		{
			syslog(LOG_ERR, "Could not open tty");
			exit(1);
		}
		int fd1 = dup(0);
		if (fd1 < 0) {
			syslog(LOG_ERR, "Failed to duplicate fd 0 (first time): %s", strerror(errno));
		}
		int fd2 = dup(0);
		if (fd2 < 0) {
			syslog(LOG_ERR, "Failed to duplicate fd 0 (second time): %s", strerror(errno));
		}

		tcsetpgrp(0, getpid());

		/* The pseudo-terminal allocated to the client is configured to operate in
		 * cooked mode, and with XTABS CRMOD enabled (see tty(4)).
		 */

		tcgetattr(0, &termbuf);
		termbuf.c_lflag |= ECHO; /* if we use readline we dont want this */
		termbuf.c_oflag |= ONLCR | XTABS;
		termbuf.c_iflag |= ICRNL;
		termbuf.c_iflag &= ~IXOFF;
		/*termbuf.c_lflag &= ~ICANON;*/
		tcsetattr(0, TCSANOW, &termbuf);

		/* exec shell, with correct argv and env */
		execv(loginpath, (char *const *)argv_init);

		/* NOT REACHED */
		syslog(LOG_ERR, "execv error");
		exit(1);
	}

	ts->shell_pid = pid;

	return ts;
}

static void 
free_session(struct tsession *ts)
{
	struct tsession *t = sessions;

	/* Unlink this telnet session from the session list.  */
	if (t == ts)
		sessions = ts->next;
	else
	{
		while (t->next != ts)
			t = t->next;
		t->next = ts->next;
	}

	kill(ts->shell_pid, SIGKILL);

	wait4(ts->shell_pid, NULL, 0, NULL);

	close(ts->ptyfd);
	close(ts->sockfd);

	if (ts->ptyfd == maxfd || ts->sockfd == maxfd)
		maxfd--;
	if (ts->ptyfd == maxfd || ts->sockfd == maxfd)
		maxfd--;

	free(ts);
}

// create a function for a thread, so we can use it in the main function
static void *
simple_telnetd_thread(void *arg)
{
	sockaddr_type sa;
	int master_fd;
	fd_set rdfdset, wrfdset;
	int selret;
	int on = 1;
	uint16_t portnbr = arg ? *(uint16_t *)arg : 2323;
	int maxlen, w, r;
	free(arg);
	debug(LOG_INFO, "Starting telnetd on port %d\n", portnbr);

	if (access(loginpath, X_OK) < 0)
	{
		debug(LOG_ERR, "No login shell found at %s\n", loginpath);
		return NULL;
	}

	argv_init[0] = loginpath;
	sessions = 0;

	/* Grab a TCP socket.  */
	master_fd = socket(SOCKET_TYPE, SOCK_STREAM, 0);
	if (master_fd < 0)
	{
		debug(LOG_ERR, "Unable to create socket\n");
		return NULL;
	}
	(void)setsockopt(master_fd, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on));

	/* Set it to listen to specified port.  */
	memset((void *)&sa, 0, sizeof(sa));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(portnbr);

	if (bind(master_fd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
	{
		debug(LOG_ERR, "Failed to bind socket: %s\n", strerror(errno));
		close(master_fd);
		return NULL;
	}

	if (listen(master_fd, 1) < 0)
	{
		debug(LOG_ERR, "Socket failed to listen\n");
		close(master_fd);
		return NULL;
		
	}

	maxfd = master_fd;

	do
	{
		struct tsession *ts;

		FD_ZERO(&rdfdset);
		FD_ZERO(&wrfdset);

		/* select on the master socket, all telnet sockets and their
		 * ptys if there is room in their respective session buffers.
		 */

		FD_SET(master_fd, &rdfdset);

		ts = sessions;
		while (ts)
		{
			/* buf1 is used from socket to pty
			 * buf2 is used from pty to socket
			 */
			if (ts->size1 > 0)
			{
				FD_SET(ts->ptyfd, &wrfdset); /* can write to pty */
			}
			if (ts->size1 < BUFSIZE)
			{
				FD_SET(ts->sockfd, &rdfdset); /* can read from socket */
			}
			if (ts->size2 > 0)
			{
				FD_SET(ts->sockfd, &wrfdset); /* can write to socket */
			}
			if (ts->size2 < BUFSIZE)
			{
				FD_SET(ts->ptyfd, &rdfdset); /* can read from pty */
			}
			ts = ts->next;
		}

		selret = select(maxfd + 1, &rdfdset, &wrfdset, 0, 0);

		if (!selret)
			break;
		/* First check for and accept new sessions.  */
		if (FD_ISSET(master_fd, &rdfdset))
		{
			int fd;
			socklen_t salen;

			salen = sizeof(sa);
			if ((fd = accept(master_fd, (struct sockaddr *)&sa,
							 &salen)) < 0)
			{
				continue;
			}
			else
			{
				/* Create a new session and link it into
					our active list.  */
				struct tsession *new_ts = make_new_session(fd);
				if (new_ts)
				{
					new_ts->next = sessions;
					sessions = new_ts;
					if (fd > maxfd)
						maxfd = fd;
				}
				else
				{
					close(fd);
				}
			}
		}

		/* Then check for data tunneling.  */
		ts = sessions;
		while (ts)
		{									  /* For all sessions...  */
			struct tsession *next = ts->next; /* in case we free ts. */

			if (ts->size1 && FD_ISSET(ts->ptyfd, &wrfdset))
			{
				int num_totty;
				char *ptr;
				/* Write to pty from buffer 1.  */

				ptr = remove_iacs(ts, &num_totty);

				w = write(ts->ptyfd, ptr, num_totty);
				if (w < 0)
				{
					free_session(ts);
					ts = next;
					continue;
				}
				ts->wridx1 += w;
				ts->size1 -= w;
				if (ts->wridx1 == BUFSIZE)
					ts->wridx1 = 0;
			}

			if (ts->size2 && FD_ISSET(ts->sockfd, &wrfdset))
			{
				/* Write to socket from buffer 2.  */
				maxlen = MIN(BUFSIZE - ts->wridx2, ts->size2);
				w = write(ts->sockfd, ts->buf2 + ts->wridx2, maxlen);
				if (w < 0)
				{
					free_session(ts);
					ts = next;
					continue;
				}
				ts->wridx2 += w;
				ts->size2 -= w;
				if (ts->wridx2 == BUFSIZE)
					ts->wridx2 = 0;
			}

			if (ts->size1 < BUFSIZE && FD_ISSET(ts->sockfd, &rdfdset))
			{
				/* Read from socket to buffer 1. */
				maxlen = MIN(BUFSIZE - ts->rdidx1,
							 BUFSIZE - ts->size1);
				r = read(ts->sockfd, ts->buf1 + ts->rdidx1, maxlen);
				if (!r || (r < 0 && errno != EINTR))
				{
					free_session(ts);
					ts = next;
					continue;
				}
				if (!*(ts->buf1 + ts->rdidx1 + r - 1))
				{
					r--;
					if (!r)
						continue;
				}
				ts->rdidx1 += r;
				ts->size1 += r;
				if (ts->rdidx1 == BUFSIZE)
					ts->rdidx1 = 0;
			}

			if (ts->size2 < BUFSIZE && FD_ISSET(ts->ptyfd, &rdfdset))
			{
				/* Read from pty to buffer 2.  */
				maxlen = MIN(BUFSIZE - ts->rdidx2,
							 BUFSIZE - ts->size2);
				r = read(ts->ptyfd, ts->buf2 + ts->rdidx2, maxlen);
				if (!r || (r < 0 && errno != EINTR))
				{
					free_session(ts);
					ts = next;
					continue;
				}
				ts->rdidx2 += r;
				ts->size2 += r;
				if (ts->rdidx2 == BUFSIZE)
					ts->rdidx2 = 0;
			}

			if (ts->size1 == 0)
			{
				ts->rdidx1 = 0;
				ts->wridx1 = 0;
			}
			if (ts->size2 == 0)
			{
				ts->rdidx2 = 0;
				ts->wridx2 = 0;
			}
			ts = next;
		}
	} while (1);

	return 0;
}

int 
simple_telnetd_start(uint16_t port)
{
	pthread_t thread;
	uint16_t *port_ptr = malloc(sizeof(uint16_t));
	*port_ptr = port;
	pthread_create(&thread, NULL, simple_telnetd_thread, port_ptr);
	return 0;
}