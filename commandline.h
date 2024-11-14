/* vim: set et sw=4 ts=4 sts=4 : */
/*
 * Copyright (C) 2022-2024 Liu Dengfeng <https://github.com/liudf0716>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by 
 * the Free Software Foundation
 */

/** @file commandline.h
    @brief Command line argument handling
*/

#ifndef XFRPC_COMMANDLINE_H
#define XFRPC_COMMANDLINE_H

/**
 * @brief Parses command line arguments and configures the application
 * @param argc Number of command line arguments
 * @param argv Array of command line argument strings
 */
void parse_commandline(int argc, char **argv);

/**
 * @brief Gets the current daemon status
 * @return Returns the daemon status (1 if running as daemon, 0 otherwise)
 */
int get_daemon_status(void);

#endif /* XFRPC_COMMANDLINE_H */
