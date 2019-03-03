#pragma once

#include "compressor.h"
#include "config.h"

extern int ifindex;
int load_xdp_prog(struct service_def **services, struct forwarding_rule **forwarding, struct config *cfg);
