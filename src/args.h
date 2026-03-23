#ifndef ARGS_H
#define ARGS_H

#define DEFAULT_TIMEOUT 1000

typedef struct {
    int show_help;
    int list_interfaces;

    char interface[64];

    int timeout_in_ms;

} program_args_t;

int parse_args(int argc, char **argv, program_args_t *args);

#endif