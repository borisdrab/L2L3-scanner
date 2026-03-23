#include "args.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int parse_args(int argc, char **argv, program_args_t *args) {
    args->show_help = 0;
    args->list_interfaces = 0;
    args->interface[0] = '\0';
    args->timeout_in_ms = DEFAULT_TIMEOUT;

    if (argc == 1) {
        fprintf(stderr, "Error: no argumentz provided\n");
        return 1;
    }

    for (int index = 1; index < argc; index++) {

        if (strcmp(argv[index], "-h") == 0 || strcmp(argv[index], "--help") == 0) {
            args->show_help = 1;
        }

        else if (strcmp(argv[index], "-i") == 0) {
            if (index + 1 < argc && argv[index+1][0] != '-') {
                strncpy(args->interface, argv[index + 1], sizeof(args->interface) - 1);
                
                index++;
            }
            else {
                args->list_interfaces = 1;
            }
        }
        else {
            fprintf(stderr, "Error: unknown argumnent '%s'\n", argv[index]);
            return 1;
        }
    }

    return 0;
}