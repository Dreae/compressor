#pragma once

#include <stdint.h>

typedef enum service_proto {
    PROTO_TCP,
    PROTO_UDP
} service_proto;

struct service_def {
    uint16_t port;
    service_proto proto;
};