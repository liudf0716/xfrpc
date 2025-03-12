#ifndef IOD_PROTO_H
#define IOD_PROTO_H

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

#define IOD_MAGIC       0xEFEFB0B0

#define IOD_SET_VIP     0x102
#define IOD_SET_VIP_ACK 0x202
#define IOD_GET_VIP     0x104
#define IOD_GET_VIP_ACK 0x204

struct iod_header {
    uint32_t magic;
    uint32_t type;
    uint64_t unique_id;
    uint32_t vip4;
    uint32_t length;
    uint8_t data[0];
};

bool is_valid_iod_header(const struct iod_header *header);
bool is_local_iod_command(uint32_t type);

#endif // IOD_PROTO_H