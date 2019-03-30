// Copyright (C) 2019 dreae
// 
// This file is part of compressor.
// 
// compressor is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// 
// compressor is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
// 
// You should have received a copy of the GNU General Public License
// along with compressor.  If not, see <http://www.gnu.org/licenses/>.

#pragma once

#include <stdint.h>

struct a2s_info_entry {
    uint64_t age;
    uint8_t data[255];
    uint16_t data_len;
};