#include "args.h"

#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <stdlib.h>


static int convert_param_to_timeout (const char *text, int *value) {
    char *end = NULL;
    long parsed_value = strtol(text, &end, 10);

    if (text[0] == '\0' || *end != '\0') {
        return 0;
    }

    if(parsed_value <= 0 ||  parsed_value > 600000) {
        return 0;
    }

    *value = (int)parsed_value;
    return 1;

}

int parse_args(int argc, char **argv, program_args_t *args) {
    args->show_help = 0;
    args->list_interfaces = 0;
    args->interface[0] = '\0';
    args->interface_set = 0;
    args->timeout_in_ms = DEFAULT_TIMEOUT;
    args->subnet_count = 0;

    if (argc == 1) {
        fprintf(stderr, "Error: no arguments provided\n");
        return 1;
    }

    for (int index = 1; index < argc; index++) {

        if (strcmp(argv[index], "-h") == 0 || strcmp(argv[index], "--help") == 0) {
            args->show_help = 1;
        }

        else if (strcmp(argv[index], "-i") == 0) {
            if (index + 1 >= argc) {
                args->list_interfaces = 1;
            }
            else if (argv[index + 1][0] == '-') {
                fprintf(stderr, "Erorr: missing interface after -i\n");
                return 1;
            }
            else {
                strncpy(args->interface, argv[index + 1], sizeof(args->interface) - 1);
                args->interface[sizeof(args->interface) - 1] = '\0';
                args->interface_set = 1;
                index++;
            }
        }

        else if (strcmp(argv[index], "-w") == 0) {
            if (index + 1 >= argc) {
                fprintf(stderr, "Error: missing timeout after -w argument\n");
                return 1;
            }
            if (!convert_param_to_timeout(argv[index+1], &args->timeout_in_ms)) { 
                fprintf(stderr, "Error: invalid timeout '%s'\n", argv[index + 1]);
                return 1;
            }

            index++;
        }

        else if (strcmp(argv[index], "-s") == 0) {
            if (index + 1 >= argc) {
                fprintf(stderr, "Error: missing subnet after -s\n");
                return 1;
            }

            if (args->subnet_count >= MAX_SUBNETS) {
                fprintf(stderr, "Error: too many subnets\n");
                return 1;
            } 

            args->subnets[args->subnet_count++] = argv[index + 1];
            index++;
        }

        else {
            fprintf(stderr, "Error: unknown argument '%s'\n", argv[index]);
            return 1;
        }
    }

    if (args->show_help) {
        return 0;
    }

    if (args->list_interfaces) {
        return 0;
    }

    if (!args->interface_set) {
        fprintf(stderr, "Error: interface not specified\n");
        return 1;
    }

    if (args->subnet_count == 0) {
        fprintf(stderr, "Error: at least one subnet must be specified with -s\n");
        return 1;
    }
    return 0;

}
