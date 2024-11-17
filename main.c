
// SPDX-License-Identifier: GPL-3.0-only
/*
 * Copyright (c) 2023 Dengfeng Liu <liudf0716@gmail.com>
 */

#include "xfrpc.h"
#include "commandline.h"
#include "login.h"

int main(int argc, char **argv)
{
	parse_commandline(argc, argv);
	init_login();
	xfrpc_loop();
}
