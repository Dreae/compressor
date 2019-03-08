#pragma once

#include <stdint.h>

struct a2s_info_entry {
    uint64_t age;
    uint8_t data[255];
    uint16_t data_len;
};