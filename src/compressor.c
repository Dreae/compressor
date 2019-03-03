#include <net/if.h>
#include <sys/resource.h>
#include <libconfig.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "compressor.h"

int ifindex;
#include "compressor_filter_user.h"

struct service_def *parse_service(const char *service) {
    char *buffer = malloc(strlen(service));
    strcpy(buffer, service);

    char *proto = strtok(buffer, "/");
    char *port = strtok(NULL, "/");
    uint16_t iport = atoi(port);
    if (iport == 0) {
        fprintf(stderr, "Invalid port defined for service %s\n", service);
        return NULL;
    }

    if (strcmp(proto, "tcp")) {
        struct service_def *def = malloc(sizeof(struct service_def));
        def->port = iport;
        def->proto = PROTO_TCP;
        
        return def;
    } else if (strcmp(proto, "udp")) {
        struct service_def *def = malloc(sizeof(struct service_def));
        def->port = iport;
        def->proto = PROTO_UDP;

        return def;
    } else {
        fprintf(stderr, "Invalid protocol defined for service %s\n", service);
        return NULL;
    }
}

void free_array(void **array) {
    void *elem;
    int idx = 0;
    while ((elem = array[idx]) != NULL) {
        free(elem);
    }

    free(array);
}

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

        config_setting_t *services = config_lookup(&config, "services");
        struct service_def **service_defs = calloc(sizeof(struct service_def *), 65535 * 2);
        int num_service = 0;
        if (services) {
            const char *service;
            int idx = 0;
            while ((service = config_setting_get_string_elem(services, idx)) != NULL) {
                struct service_def *def = parse_service(service);
                if (def != NULL) {
                    service_defs[num_service] = def;
                    num_service++;
                }
            }
        }

        free_array((void **)service_defs);

        ifindex = if_nametoindex(interface);
        if (!ifindex) {
            perror("Error getting interface");
            return 1;
        }

        if ((res = load_xdp_prog(service_defs)) != 0) {
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
