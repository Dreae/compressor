#pragma once

#include "compressor.h"

extern int ifindex;
int load_xdp_prog(struct service_def **services);
