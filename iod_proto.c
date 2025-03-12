#include "iod_proto.h"

bool is_valid_iod_header(const struct iod_header *header)
{
    return header && header->magic == htonl(IOD_MAGIC);
}

bool is_local_iod_command(uint32_t type)
{
    return type == IOD_SET_VIP || type == IOD_GET_VIP;
}