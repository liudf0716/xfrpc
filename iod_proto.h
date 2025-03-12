#ifndef IOD_PROTO_H
#define IOD_PROTO_H

#include <stdint.h>

#define IOD_MAGIC 0xEFEFB0B0

struct iod_header {
    uint32_t magic;
    uint32_t type;
    uint64_t unique_id;
    uint32_t vip4;
    uint32_t length;
    uint8_t data[0];
};

#endif // IOD_PROTO_H