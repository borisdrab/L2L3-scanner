#ifndef ARGS_H
#define ARGS_H

#define MAX_SUBNETS 32                  // maximum number of subnets
#define DEFAULT_TIMEOUT 1000            // default timeout in milliseconds used when -w is not provided

typedef struct {                        // parsed command-line config
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
