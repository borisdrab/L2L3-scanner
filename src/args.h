#ifndef ARGS_H
#define ARGS_H

#define MAX_SUBNETS 32
#define DEFAULT_TIMEOUT 1000

typedef struct {
    int show_help;
    int list_interfaces;

    char interface[64];
    int interface_set;

    int timeout_in_ms;

    char *subnets[MAX_SUBNETS];
    int subnet_count;

} program_args_t;

int parse_args(int argc, char **argv, program_args_t *args);

#endif
