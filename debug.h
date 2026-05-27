
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#ifndef XFRPC_DEBUG_H
#define XFRPC_DEBUG_H


#include <string.h>
#include <syslog.h>

#define __FILENAME__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)

typedef struct _debug_conf {
    int debuglevel;      /**< @brief Debug information verbosity */
    int log_stderr;      /**< @brief Output log to stdout */
    int log_syslog;      /**< @brief Output log to syslog */
    int syslog_facility; /**< @brief facility to use when using syslog for logging */
} debugconf_t;

extern debugconf_t debugconf;

/** Used to output messages.
 * The messages will include the filename and line number, and will be sent to syslog if so configured in the config file 
 * @param level Debug level
 * @param format... sprintf like format string
 */
#ifdef XFRPC_DEBUG
#define debug(level, format...) _debug(__FILENAME__ , __LINE__, level, format)
#else
#define debug(level, format...) do { if (level <= LOG_ERR) _debug(__FILENAME__ , __LINE__, level, format); } while(0)
#endif

/** @internal */
void _debug(const char *, int, int, const char *, ...);

#endif
