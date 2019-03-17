#include "compressor.h"
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include "config.h"

struct service_def *parse_service(const char *service) {
    char buffer[128];
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

    if (strcmp(proto, "tcp") == 0) {
        struct service_def *def = calloc(1, sizeof(struct service_def));
        def->port = iport;
        def->proto = PROTO_TCP;
        
        return def;
    } else if (strcmp(proto, "udp") == 0) {
        struct service_def *def = calloc(1, sizeof(struct service_def));
        def->port = iport;
        def->proto = PROTO_UDP;

        return def;
    } else {
        fprintf(stderr, "Invalid protocol defined for service %s\n", service);
        return NULL;
    }
}

struct forwarding_rule *parse_forwarding_rule(config_setting_t *cfg_rule) {
    const char *bindstr;
    const char *deststr;

    int get_bindaddr = config_setting_lookup_string(cfg_rule, "bind", &bindstr);
    int get_destaddr = config_setting_lookup_string(cfg_rule, "dest", &deststr);
    if (!get_bindaddr || !get_destaddr) {
        fprintf(stderr, "Error parsing forwarding rule\n");
        return NULL;
    }

    char bindbuffer[32];
    strcpy(bindbuffer, bindstr);
    char *bindaddr = strtok(bindbuffer, ":");
    char *bindport = strtok(NULL, ":");
    if (!bindaddr || !bindport) {
        fprintf(stderr, "Error parsing bind address %s\n", bindstr);
        return NULL;
    }

    char destbuffer[32];
    strcpy(destbuffer, deststr);
    char *destaddr = strtok(destbuffer, ":");
    char *destport = strtok(NULL, ":");
    if (!destaddr || !destport) {
        fprintf(stderr, "Error parsing bind address %s\n", deststr);
        return NULL;
    }

    struct in_addr bind_inet = { 0 };
    if (!inet_aton(bindaddr, &bind_inet)) {
        fprintf(stderr, "Error parsing ip address %s\n", bindaddr);
        return NULL;
    }
    uint16_t bind_port = atoi(bindport);
    if (!bind_port) {
        fprintf(stderr, "Error parsing port %s\n", bindport);
        return NULL;
    }

    struct in_addr dest_inet = { 0 };
    if (!inet_aton(destaddr, &dest_inet)) {
        fprintf(stderr, "Error parsing ip address %s\n", destaddr);
        return NULL;
    }

    struct in_addr inner_inet = { 0 };
    const char *inner_addr;
    if (config_setting_lookup_string(cfg_rule, "internal_ip", &inner_addr) == CONFIG_TRUE) {
        if (!inet_aton(inner_addr, &inner_inet)) {
            fprintf(stderr, "Error parsing IP address %s\n", inner_addr);
            return NULL;
        }
    } else {
        inner_inet.s_addr = dest_inet.s_addr;
    }

    uint16_t dest_port = atoi(destport);
    if (!dest_port) {
        fprintf(stderr, "Error parsing port %s\n", destport);
        return NULL;
    }

    const char *steamport;
    uint16_t steam_port = 26901;
    int get_steamport = config_setting_lookup_string(cfg_rule, "steam_port", &steamport);
    if (get_steamport) {
        steam_port = atoi(steamport);
        if (!steam_port) {
            fprintf(stderr, "Error parsing steam port %s\n", steamport);
            return NULL;
        }
    }

    int a2s_info_cache = 0;
    int get_a2sinfo = config_setting_lookup_int(cfg_rule, "a2s_info_cache", &a2s_info_cache);
    if (get_a2sinfo == CONFIG_FALSE) {
        a2s_info_cache = 0;
    }

    int cache_time = 0;
    int get_cachetime = config_setting_lookup_int(cfg_rule, "cache_time", &cache_time);
    if (get_cachetime == CONFIG_FALSE) {
        cache_time = 60;
    }

    struct forwarding_rule *rule = malloc(sizeof(struct forwarding_rule));
    rule->bind_addr = bind_inet.s_addr;
    rule->bind_port = bind_port;

    rule->to_addr = dest_inet.s_addr;
    rule->to_port = dest_port;
    rule->steam_port = steam_port;
    rule->inner_addr = inner_inet.s_addr;
    rule->a2s_info_cache = a2s_info_cache;
    // Convert to nanoseconds
    rule->cache_time = cache_time * 1e9;
    return rule;
}

struct in_addr **parse_ip_whitelist(config_setting_t *whitelist) {
    if (!whitelist) {
        fprintf(stderr, "Warning: no IP whitelist found\n");
        fprintf(stderr, "Whithout whitelisting at least a DNS service srcds will be unable to talk to Valve's master server\n");
        return calloc(1, sizeof(void *));
    }

    if (config_setting_is_list(whitelist) == CONFIG_FALSE) {
        fprintf(stderr, "Error: IP whitelist must be a list\n");
        return calloc(1, sizeof(void *));
    }

    int len = config_setting_length(whitelist);
    struct in_addr **array = calloc(len, sizeof(void *));
    if (len != 0) {
        int idx = 0;
        for (int c = 0; c < len; c++) {
            const char *ip = config_setting_get_string_elem(whitelist, c);
            if (!ip) {
                fprintf(stderr, "Error reading IP whitelist, element is null\n");
                continue;
            }
            array[idx] = calloc(1, sizeof(struct in_addr));
            if (!inet_aton(ip, array[idx])) {
                fprintf(stderr, "Error parsing whitelisted IP %s\n", ip);
                continue;
            }
            
            idx++;
        }
    }

    return array;
}