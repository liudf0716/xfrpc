/*******************************************************************************
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of
 * the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 ******************************************************************************/

/** @file debug.c
    @brief Debug output routines
    @author Copyright (C) 2023 Dengfeng Liu <liudf0716@gmail.com>
*/

#include <stdio.h>
#include <errno.h>
#include <syslog.h>
#include <stdarg.h>
#include <time.h>
#include <unistd.h>
#include <signal.h>

#include "debug.h"

#define	PROGNAME	"xfrpc"

debugconf_t debugconf = {
    .debuglevel = LOG_INFO,
    .log_stderr = 1,
    .log_syslog = 0,
    .syslog_facility = 0
};


void _debug(const char *filename, int line, int level, const char *format, ...)
{
    if (level > debugconf.debuglevel) {
        return;
    }

    char buf[32] = {0};
    va_list vlist;
    time_t ts = time(NULL);
    sigset_t block_chld;

    // Block SIGCHLD signal
    sigemptyset(&block_chld);
    sigaddset(&block_chld, SIGCHLD);
    sigprocmask(SIG_BLOCK, &block_chld, NULL);

    // Write to stderr if needed
    if (level <= LOG_WARNING || debugconf.log_stderr) {
        fprintf(stderr, "[%d][%.24s][%u](%s:%d) ", 
                level, ctime_r(&ts, buf), getpid(), filename, line);
        va_start(vlist, format);
        vfprintf(stderr, format, vlist);
        va_end(vlist);
        fputc('\n', stderr);
    }

    // Write to syslog if enabled
    if (debugconf.log_syslog) {
        openlog(PROGNAME, LOG_PID, debugconf.syslog_facility);
        va_start(vlist, format);
        vsyslog(level, format, vlist);
        va_end(vlist);
        closelog();
    }

    // Unblock SIGCHLD signal
    sigprocmask(SIG_UNBLOCK, &block_chld, NULL);
}
