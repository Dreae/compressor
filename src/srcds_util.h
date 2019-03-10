#pragma once

#include <stdint.h>

static __always_inline int check_srcds_header(const uint8_t *addr, uint8_t id) {
    if ((*addr++) == 0xff && (*addr++) == 0xff && (*addr++) == 0xff && (*addr++) == 0xff && (*addr) == id) {
        return 1;
    }

    return 0;
}