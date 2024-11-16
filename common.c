/* vim: set et ts=4 sts=4 sw=4 : */
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

/** @file common.c
    @brief xfrp common function implemented
    @author Copyright (C) 2016 Dengfeng Liu <liu_df@qq.com>
*/

#include "uthash.h"
#include "common.h"

uint64_t ntoh64(const uint64_t input)
{
#if __BYTE_ORDER == __BIG_ENDIAN
    return input;
#else
    return ((uint64_t)ntohl(input & 0xFFFFFFFF) << 32) | 
           ntohl((input >> 32) & 0xFFFFFFFF);
#endif
}

uint64_t hton64(const uint64_t input)
{
#if __BYTE_ORDER == __BIG_ENDIAN
    return input;
#else
    return ((uint64_t)htonl(input & 0xFFFFFFFF) << 32) | 
           htonl((input >> 32) & 0xFFFFFFFF);
#endif
}
