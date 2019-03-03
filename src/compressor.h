#pragma once

#include <stdint.h>

#define PROTO_TCP 1
#define PROTO_UDP 2

struct service_def {
    uint16_t port;
    uint8_t proto;
};