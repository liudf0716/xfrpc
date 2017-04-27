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
#include <syslog.h>

#include "xkcp_config.h"
#include "commandline.h"
#include "debug.h"
#include "version.h"

static void usage(void);

/** @internal
 * @brief Print usage
 *
 * Prints usage, called when wifidog is run with -h or with an unknown option
 */
static void
usage(void)
{
    fprintf(stdout, "Usage: xkcp_client [options]\n");
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
    int i;

    xkcp_config *config = xkcp_get_config();

    while (-1 != (c = getopt(argc, argv, "c:hfd:sw:vx:i:a:"))) {


        switch (c) {

        case 'h':
            usage();
            exit(1);
            break;

        case 'c':
            if (optarg) {
                free(config->config_file);
                config->config_file = safe_strdup(optarg);
            }
            break;

        case 'f':
            config->daemon = 0;
            debugconf.log_stderr = 1;
            break;

        case 'd':
            if (optarg) {
                debugconf.debuglevel = atoi(optarg);
            }
            break;

        case 'v':
            fprintf(stdout, "This is xkcp client version " VERSION "\n");
            exit(1);
            break;

        default:
            usage();
            exit(1);
            break;

        }
    }
}
