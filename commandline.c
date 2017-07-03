/* vim: set et sw=4 ts=4 sts=4 : */
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

/** @file commandline.c
    @brief Command line argument handling
    @author Copyright (C) 2004 Philippe April <papril777@yahoo.com>
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>


#include "config.h"
#include "commandline.h"
#include "debug.h"
#include "version.h"

typedef void signal_func (int);

static signal_func *set_signal_handler (int signo, signal_func * func);
static void usage(const char *appname);

static int is_daemon = 1;

static char *confile = NULL;

/*
 * Fork a child process and then kill the parent so make the calling
 * program a daemon process.
 */
static void 
makedaemon (void)
{
	if (fork () != 0)
			exit (0);

	setsid ();
	set_signal_handler (SIGHUP, SIG_IGN);

	if (fork () != 0)
			exit (0);

	umask (0177);

	close (0);
	close (1);
	close (2);
}

/*
 * Pass a signal number and a signal handling function into this function
 * to handle signals sent to the process.
 */
static signal_func *
set_signal_handler (int signo, signal_func * func)
{
        struct sigaction act, oact;

        act.sa_handler = func;
        sigemptyset (&act.sa_mask);
        act.sa_flags = 0;
        if (signo == SIGALRM) {
#ifdef SA_INTERRUPT
                act.sa_flags |= SA_INTERRUPT;   /* SunOS 4.x */
#endif
        } else {
#ifdef SA_RESTART
                act.sa_flags |= SA_RESTART;     /* SVR4, 4.4BSD */
#endif
        }

        if (sigaction (signo, &act, &oact) < 0)
                return SIG_ERR;

        return oact.sa_handler;
}

int 
get_daemon_status()
{
	return is_daemon;
}

/** @internal
 * @brief Print usage
 *
 * Prints usage, called when wifidog is run with -h or with an unknown option
 */
static void
usage(const char *appname)
{
    fprintf(stdout, "Usage: %s [options]\n", appname);
    fprintf(stdout, "\n");
    fprintf(stdout, "options:\n");
    fprintf(stdout, "  -c [filename] Use this config file\n");
    fprintf(stdout, "  -f            Run in foreground\n");
    fprintf(stdout, "  -d <level>    Debug level\n");
    fprintf(stdout, "  -h            Print usage\n");
    fprintf(stdout, "  -v            Print version information\n");
    fprintf(stdout, "\n");
}

/** Uses getopt() to parse the command line and set configuration values
 * also populates restartargv
 */
void
parse_commandline(int argc, char **argv)
{
    int c;
	int flag = 0;
	
    while (-1 != (c = getopt(argc, argv, "c:hfd:sw:vx:i:a:"))) {


        switch (c) {

        case 'h':
            usage(argv[0]);
            exit(1);
            break;

        case 'c':
            if (optarg) {
				confile = strdup(optarg); //never free it
                if (! confile)
                    exit(0);

				flag = 1;
            }
            break;

        case 'f':
            is_daemon = 0;
            debugconf.log_stderr = 1;
            break;

        case 'd':
            if (optarg) {
                debugconf.debuglevel = atoi(optarg);
            }
            break;

        case 'v':
            fprintf(stdout, "This is %s version " VERSION "\n", argv[0]);
            exit(1);
            break;

        default:
            usage(argv[0]);
            exit(1);
            break;

        }
    }
	
	if (!flag) {
		usage(argv[0]);
		exit(0);
	}
	
	load_config(confile);
	
	if (is_daemon) {
		makedaemon();
	}
}
