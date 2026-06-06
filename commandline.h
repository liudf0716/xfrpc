
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
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

/**
 * @brief Returns the path to the configuration file.
 * @return Pointer to config file path (do not free)
 */
const char *get_config_file(void);

/**
 * @brief Checks whether a SIGHUP-triggered reload is pending.
 * @return 1 if reload requested, 0 otherwise
 */
int check_reload_flag(void);

/**
 * @brief Clears the reload flag after handling.
 */
void clear_reload_flag(void);

#endif /* XFRPC_COMMANDLINE_H */
