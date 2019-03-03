#include <net/if.h>
#include <sys/resource.h>
#include <libconfig.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int ifindex;
#include "compressor_filter_user.h"

int main(int argc, char **argv) {
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &r)) {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        return 1;
    }

    config_t config;
    config_init(&config);

    FILE *fd = fopen("/etc/compressor/compressor.conf", "r");
    if (fd) {
        int res = config_read(&config, fd);
        if (res == CONFIG_FALSE) {
            fprintf(stderr, "Error parsing configuration file: %s\n", config_error_text(&config));
            return 1;
        }
        const char *interface;
        if (config_lookup_string(&config, "interface", &interface) == CONFIG_FALSE) {
            fprintf(stderr, "Error: No interface defined in configuration file\n");
            return 1;
        }

        ifindex = if_nametoindex(interface);
        if (!ifindex) {
            perror("Error getting interface");
            return 1;
        }

        if ((res = load_xdp_prog()) != 0) {
            return res;
        }
    } else {
        perror("Error reading configuration file");
        return 1;
    }

    while (1) {
        sleep(2);
    }
    
    return 0;
}
