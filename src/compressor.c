#include <net/if.h>
#include <sys/resource.h>
#include <libconfig.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>

#include "compressor.h"
#include "config.h"

int ifindex;
#include "compressor_filter_user.h"

struct service_def *parse_service(const char *service) {
    char *buffer = malloc(strlen(service) + 1);
    strcpy(buffer, service);

    char *port = strtok(buffer, "/");
    char *proto = strtok(NULL, "/");
    if (port == NULL || proto == NULL) {
        fprintf(stderr, "Error parsing service definition: %s\n", service);
        return NULL;
    }

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

int get_iface_mac_address(const char *interface, uint16_t *addr) {
    char filename[256];
    snprintf(filename, sizeof(filename), "/sys/class/net/%s/address", interface);
    
    FILE *fd = fopen(filename, "r");
    if (!fd) {
        perror("Error reading interface MAC address");
        return 0;
    }

    uint8_t bytes[6];
    int values[6];
    if (fscanf(fd, "%x:%x:%x:%x:%x:%x%*c", &values[0], &values[1], &values[2], &values[3], &values[4], &values[5]) != 6) {
        fprintf(stderr, "Unable to read MAC address for interface %s", interface);
        return 0;
    }

    for (int i = 0; i < 6; i++) {
        bytes[i] = (uint8_t)values[i];
    }

    memcpy(addr, bytes, 6);
    return 1;
}

void free_array(void **array) {
    void *elem;
    int idx = 0;
    while ((elem = array[idx]) != NULL) {
        free(elem);
        idx++;
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

                idx++;
            }
        }

        ifindex = if_nametoindex(interface);
        if (!ifindex) {
            perror("Error getting interface");
            return 1;
        }

        uint16_t hwaddr[3];
        if (!get_iface_mac_address(interface, hwaddr)) {
            return 1;
        }
        struct config cfg = { 0 };
        cfg.hw1 = htons(hwaddr[0]);
        cfg.hw2 = htons(hwaddr[1]);
        cfg.hw3 = htons(hwaddr[2]);

        if ((res = load_xdp_prog(service_defs, &cfg)) != 0) {
            return res;
        }

        free_array((void **)service_defs);
    } else {
        perror("Error reading configuration file");
        return 1;
    }

    while (1) {
        sleep(2);
    }
    
    return 0;
}
