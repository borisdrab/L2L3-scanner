#include <criterion/criterion.h>
#include <criterion/new/assert.h>

#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define BIN_PATH "./ipk-L2L3-scan"
#define OUTPUT_BUFFER_SIZE 65536

typedef struct {
    int exit_code;
    char output[OUTPUT_BUFFER_SIZE];
} command_result_t;

// ensure compiled binary exists and is executable
static void ensure_binary_exists(void) {
    if (access(BIN_PATH, X_OK) != 0) {
        cr_fatal("Binary '%s' not found or not executable", BIN_PATH);
    }
}

// check if program runs with root (required for raw sockets)
static bool is_root(void) {
    return geteuid() == 0;
}

// select a default network interface from system
static const char *pick_default_interface(void) {
    static char selected[256];
    DIR *dir = opendir("/sys/class/net");
    if (dir == NULL) {
        return NULL;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        const char *name = entry->d_name;
        if ((name[0] == 'e' || name[0] == 'w') && strcmp(name, ".") != 0 && strcmp(name, "..") != 0) {
            strncpy(selected, name, sizeof(selected) - 1);
            selected[sizeof(selected) - 1] = '\0';
            closedir(dir);
            return selected;
        }
    }

    closedir(dir);
    return NULL;
}

static command_result_t run_command_capture(char *const argv[]) {
    command_result_t result;
    result.exit_code = -1;
    result.output[0] = '\0';

    int pipefd[2];
    if (pipe(pipefd) != 0) {
        cr_fatal("pipe() failed");
    }

    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        cr_fatal("fork() failed");
    }

    if (pid == 0) {
        close(pipefd[0]);

        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[1]);

        execv(argv[0], argv);
        perror("execv failed");
        _exit(127);
    }

    close(pipefd[1]);

    size_t total = 0;
    while (total < sizeof(result.output) - 1) {
        ssize_t n = read(pipefd[0], result.output + total, sizeof(result.output) - 1 - total);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            break;
        }
        if (n == 0) {
            break;
        }
        total += (size_t)n;
    }

    result.output[total] = '\0';
    close(pipefd[0]);

    int status = 0;
    if (waitpid(pid, &status, 0) < 0) {
        cr_fatal("waitpid() failed");
    }

    if (WIFEXITED(status)) {
        result.exit_code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        result.exit_code = 128 + WTERMSIG(status);
    } else {
        result.exit_code = -1;
    }

    return result;
}

// expect command to succeed (exit code 0)
static void assert_success(char *const argv[]) {    
    command_result_t res = run_command_capture(argv);
    cr_assert(eq(int, res.exit_code, 0),
        "Expected success, got exit code %d.\nOutput:\n%s",
        res.exit_code, res.output);
}

// expect command to fail (exit code non-zero)
static void assert_failure(char *const argv[]) {
    command_result_t res = run_command_capture(argv);
    cr_assert(res.exit_code != 0,
        "Expected failure, but command succeeded.\nOutput:\n%s",
        res.output);
}

// expect command output to contain specific substring
static void assert_output_contains(char *const argv[], const char *needle) {
    command_result_t res = run_command_capture(argv);
    cr_assert(eq(int, res.exit_code, 0),
        "Expected success, got exit code %d.\nOutput:\n%s",
        res.exit_code, res.output);
    cr_assert(strstr(res.output, needle) != NULL,
        "Expected output to contain '%s'.\nActual output:\n%s",
        needle, res.output);
}

// skip test if not running as root
static void require_root_or_skip(void) {
    if (!is_root()) {
        cr_skip_test("requires root");
    }
}

// skip test if no suitable network interface is found
static const char *require_interface_or_skip(void) {
    const char *iface = pick_default_interface();
    if (iface == NULL || iface[0] == '\0') {
        cr_skip_test("no suitable interface found");
    }
    return iface;
}

/* ---------------- Basic CLI tests ---------------- */

Test(cli_basic, help_short) {
    ensure_binary_exists();
    char *const argv[] = { BIN_PATH, "-h", NULL };
    assert_success(argv);
}

Test(cli_basic, help_long) {
    ensure_binary_exists();
    char *const argv[] = { BIN_PATH, "--help", NULL };
    assert_success(argv);
}

Test(cli_basic, interface_list) {
    ensure_binary_exists();
    char *const argv[] = { BIN_PATH, "-i", NULL };
    assert_success(argv);
}

/* ---------------- Argument validation ---------------- */

Test(arg_validation, missing_argument) {
    ensure_binary_exists();
    char *const argv[] = { BIN_PATH, NULL };
    assert_failure(argv);
}

Test(arg_validation, missing_interface) {
    ensure_binary_exists();
    char *const argv[] = { BIN_PATH, "-s", "10.10.0.0/30", NULL };
    assert_failure(argv);
}

Test(arg_validation, missing_subnet_after_s) {
    ensure_binary_exists();
    const char *iface = require_interface_or_skip();
    char *const argv[] = { BIN_PATH, "-i", (char *)iface, "-s", NULL };
    assert_failure(argv);
}

Test(arg_validation, missing_timeout_after_w) {
    ensure_binary_exists();
    const char *iface = require_interface_or_skip();
    char *const argv[] = { BIN_PATH, "-i", (char *)iface, "-w", NULL };
    assert_failure(argv);
}

Test(arg_validation, invalid_timeout_zero) {
    ensure_binary_exists();
    const char *iface = require_interface_or_skip();
    char *const argv[] = { BIN_PATH, "-i", (char *)iface, "-w", "0", "-s", "10.0.2.0/30", NULL };
    assert_failure(argv);
}

Test(arg_validation, invalid_timeout_negative) {
    ensure_binary_exists();
    const char *iface = require_interface_or_skip();
    char *const argv[] = { BIN_PATH, "-i", (char *)iface, "-w", "-5", "-s", "10.0.2.0/30", NULL };
    assert_failure(argv);
}

Test(arg_validation, invalid_timeout_text) {
    ensure_binary_exists();
    const char *iface = require_interface_or_skip();
    char *const argv[] = { BIN_PATH, "-i", (char *)iface, "-w", "ipkipk", "-s", "10.0.2.0/30", NULL };
    assert_failure(argv);
}

Test(arg_validation, invalid_timeout_too_large) {
    ensure_binary_exists();
    const char *iface = require_interface_or_skip();
    char *const argv[] = { BIN_PATH, "-i", (char *)iface, "-w", "800008", "-s", "10.0.2.0/30", NULL };
    assert_failure(argv);
}

Test(arg_validation, invalid_subnet_text) {
    ensure_binary_exists();
    const char *iface = require_interface_or_skip();
    char *const argv[] = { BIN_PATH, "-i", (char *)iface, "-s", "ooooooo00ooooo", NULL };
    assert_failure(argv);
}

Test(arg_validation, invalid_ipv4_subnet) {
    ensure_binary_exists();
    const char *iface = require_interface_or_skip();
    char *const argv[] = { BIN_PATH, "-i", (char *)iface, "-s", "10.10.0.999/30", NULL };
    assert_failure(argv);
}

Test(arg_validation, invalid_ipv6_subnet) {
    ensure_binary_exists();
    const char *iface = require_interface_or_skip();
    char *const argv[] = { BIN_PATH, "-i", (char *)iface, "-s", "fd00::gg/126", NULL };
    assert_failure(argv);
}

Test(arg_validation, invalid_ipv4_prefix) {
    ensure_binary_exists();
    const char *iface = require_interface_or_skip();
    char *const argv[] = { BIN_PATH, "-i", (char *)iface, "-s", "10.10.0.0/33", NULL };
    assert_failure(argv);
}

Test(arg_validation, invalid_ipv6_prefix) {
    ensure_binary_exists();
    const char *iface = require_interface_or_skip();
    char *const argv[] = { BIN_PATH, "-i", (char *)iface, "-s", "fd00::/129", NULL };
    assert_failure(argv);
}

Test(arg_validation, subnet_missing_prefix_ipv4) {
    ensure_binary_exists();
    const char *iface = require_interface_or_skip();
    char *const argv[] = { BIN_PATH, "-i", (char *)iface, "-s", "10.0.0.6", NULL };
    assert_failure(argv);
}

Test(arg_validation, subnet_missing_prefix_ipv6) {
    ensure_binary_exists();
    const char *iface = require_interface_or_skip();
    char *const argv[] = { BIN_PATH, "-i", (char *)iface, "-s", "fec0::6", NULL };
    assert_failure(argv);
}

Test(arg_validation, nonexistent_interface) {
    ensure_binary_exists();
    char *const argv[] = { BIN_PATH, "-i", "neexistuje", "-s", "10.10.0.0/30", NULL };
    assert_failure(argv);
}

Test(arg_validation, unknown_argument) {
    ensure_binary_exists();
    char *const argv[] = { BIN_PATH, "--xdxdxdxdxd", NULL };
    assert_failure(argv);
}

Test(arg_validation, empty_interface_string) {
    ensure_binary_exists();
    char *const argv[] = { BIN_PATH, "-i", "", "-s", "10.0.2.0/30", NULL };
    assert_failure(argv);
}

Test(arg_validation, empty_subnet_string) {
    ensure_binary_exists();
    const char *iface = require_interface_or_skip();
    char *const argv[] = { BIN_PATH, "-i", (char *)iface, "-s", "", NULL };
    assert_failure(argv);
}

Test(arg_validation, empty_timeout_string) {
    ensure_binary_exists();
    const char *iface = require_interface_or_skip();
    char *const argv[] = { BIN_PATH, "-i", (char *)iface, "-w", "", "-s", "10.0.0.0/30", NULL };
    assert_failure(argv);
}

Test(arg_validation, extra_stray_argument_after_subnet) {
    ensure_binary_exists();
    const char *iface = require_interface_or_skip();
    char *const argv[] = { BIN_PATH, "-i", (char *)iface, "-s", "10.1.1.1/30", "extra", NULL };
    assert_failure(argv);
}

Test(arg_validation, extra_stray_argument_after_interface) {
    ensure_binary_exists();
    const char *iface = require_interface_or_skip();
    char *const argv[] = { BIN_PATH, "-i", (char *)iface, "extra", "-s", "10.1.1.1/30", NULL };
    assert_failure(argv);
}

Test(arg_validation, missing_subnet_but_interface_present) {
    ensure_binary_exists();
    const char *iface = require_interface_or_skip();
    char *const argv[] = { BIN_PATH, "-i", (char *)iface, NULL };
    assert_failure(argv);
}

/* ---------------- Repeated arguments ---------------- */

Test(repeated_args, duplicated_interface_last_wins) {
    ensure_binary_exists();
    require_root_or_skip();
    const char *iface = require_interface_or_skip();
    char *const argv[] = { BIN_PATH, "-i", "lo", "-i", (char *)iface, "-s", "10.2.5.0/30", NULL };
    assert_success(argv);
}

Test(repeated_args, duplicated_timeout_last_wins) {
    ensure_binary_exists();
    require_root_or_skip();
    const char *iface = require_interface_or_skip();
    char *const argv[] = { BIN_PATH, "-i", (char *)iface, "-w", "1", "-w", "1000", "-s", "10.1.1.1/30", NULL };
    assert_success(argv);
}

/* ---------------- IPv4 edge cases ---------------- */

Test(ipv4_edge, single_host_32) {
    ensure_binary_exists();
    require_root_or_skip();
    const char *iface = require_interface_or_skip();
    char *const argv[] = { BIN_PATH, "-i", (char *)iface, "-s", "10.0.2.2/32", NULL };
    assert_success(argv);
}

Test(ipv4_edge, special_case_31) {
    ensure_binary_exists();
    require_root_or_skip();
    const char *iface = require_interface_or_skip();
    char *const argv[] = { BIN_PATH, "-i", (char *)iface, "-s", "10.0.2.0/31", NULL };
    assert_success(argv);
}

Test(ipv4_edge, small_range_29) {
    ensure_binary_exists();
    require_root_or_skip();
    const char *iface = require_interface_or_skip();
    char *const argv[] = { BIN_PATH, "-i", (char *)iface, "-s", "10.0.3.0/29", NULL };
    assert_success(argv);
}

/* ---------------- IPv6 edge cases ---------------- */

Test(ipv6_edge, single_host_128) {
    ensure_binary_exists();
    require_root_or_skip();
    const char *iface = require_interface_or_skip();
    char *const argv[] = { BIN_PATH, "-i", (char *)iface, "-s", "fec0::2/128", NULL };
    assert_success(argv);
}

Test(ipv6_edge, normalized_126) {
    ensure_binary_exists();
    require_root_or_skip();
    const char *iface = require_interface_or_skip();
    char *const argv[] = { BIN_PATH, "-i", (char *)iface, "-s", "fec0::1/126", NULL };
    assert_success(argv);
}

/* ---------------- Multiple subnets ---------------- */

Test(multi_subnet, ipv4_and_ipv6) {
    ensure_binary_exists();
    require_root_or_skip();
    const char *iface = require_interface_or_skip();
    char *const argv[] = {
        BIN_PATH, "-i", (char *)iface,
        "-s", "10.0.2.0/30",
        "-s", "fec0::2/128",
        NULL
    };
    assert_success(argv);
}

Test(multi_subnet, duplicated_ipv4_subnet_normalized) {
    ensure_binary_exists();
    require_root_or_skip();
    const char *iface = require_interface_or_skip();
    char *const argv[] = {
        BIN_PATH, "-i", (char *)iface,
        "-s", "10.0.2.0/30",
        "-s", "10.0.2.1/30",
        NULL
    };
    assert_success(argv);
}

Test(multi_subnet, duplicated_ipv6_subnet) {
    ensure_binary_exists();
    require_root_or_skip();
    const char *iface = require_interface_or_skip();
    char *const argv[] = {
        BIN_PATH, "-i", (char *)iface,
        "-s", "fec0::2/128",
        "-s", "fec0::8/128",
        NULL
    };
    assert_success(argv);
}

Test(multi_subnet, three_subnets) {
    ensure_binary_exists();
    require_root_or_skip();
    const char *iface = require_interface_or_skip();
    char *const argv[] = {
        BIN_PATH, "-i", (char *)iface,
        "-s", "100.9.6.7/30",
        "-s", "67.67.67.67/30",
        "-s", "fec3::ff/128",
        NULL
    };
    assert_success(argv);
}

/* ---------------- Integration tests ---------------- */

Test(integration, ipv4_scan_30) {
    ensure_binary_exists();
    require_root_or_skip();
    const char *iface = require_interface_or_skip();
    char *const argv[] = { BIN_PATH, "-i", (char *)iface, "-s", "10.0.2.0/30", NULL };
    assert_success(argv);
}

Test(integration, ipv4_scan_32) {
    ensure_binary_exists();
    require_root_or_skip();
    const char *iface = require_interface_or_skip();
    char *const argv[] = { BIN_PATH, "-i", (char *)iface, "-s", "10.0.2.2/32", NULL };
    assert_success(argv);
}

Test(integration, ipv6_scan_128) {
    ensure_binary_exists();
    require_root_or_skip();
    const char *iface = require_interface_or_skip();
    char *const argv[] = { BIN_PATH, "-i", (char *)iface, "-s", "fec0::2/128", NULL };
    assert_success(argv);
}

Test(integration, random_order_args) {
    ensure_binary_exists();
    require_root_or_skip();
    const char *iface = require_interface_or_skip();
    char *const argv[] = { BIN_PATH, "-s", "172.16.5.0/30", "-i", (char *)iface, NULL };
    assert_success(argv);
}

/* ---------------- Too many subnets ---------------- */

Test(arg_limits, too_many_subnets) {
    ensure_binary_exists();

    char *argv[80];
    int i = 0;
    argv[i++] = BIN_PATH;
    argv[i++] = "-i";
    argv[i++] = "enp0s1";

    argv[i++] = "-s"; argv[i++] = "100.0.0.1/30";
    argv[i++] = "-s"; argv[i++] = "100.1.0.1/30";
    argv[i++] = "-s"; argv[i++] = "100.2.0.1/30";
    argv[i++] = "-s"; argv[i++] = "100.3.0.1/30";
    argv[i++] = "-s"; argv[i++] = "100.4.0.1/30";
    argv[i++] = "-s"; argv[i++] = "100.5.0.1/30";
    argv[i++] = "-s"; argv[i++] = "100.6.0.1/30";
    argv[i++] = "-s"; argv[i++] = "100.7.0.1/30";
    argv[i++] = "-s"; argv[i++] = "100.8.0.1/30";
    argv[i++] = "-s"; argv[i++] = "100.9.0.1/30";
    argv[i++] = "-s"; argv[i++] = "100.10.0.1/30";
    argv[i++] = "-s"; argv[i++] = "100.11.0.1/30";
    argv[i++] = "-s"; argv[i++] = "100.12.0.1/30";
    argv[i++] = "-s"; argv[i++] = "100.13.0.1/30";
    argv[i++] = "-s"; argv[i++] = "100.14.0.1/30";
    argv[i++] = "-s"; argv[i++] = "100.15.0.1/30";
    argv[i++] = "-s"; argv[i++] = "100.16.0.1/30";
    argv[i++] = "-s"; argv[i++] = "100.17.0.1/30";
    argv[i++] = "-s"; argv[i++] = "100.18.0.1/30";
    argv[i++] = "-s"; argv[i++] = "100.19.0.1/30";
    argv[i++] = "-s"; argv[i++] = "100.20.0.1/30";
    argv[i++] = "-s"; argv[i++] = "100.21.0.1/30";
    argv[i++] = "-s"; argv[i++] = "100.22.0.1/30";
    argv[i++] = "-s"; argv[i++] = "100.23.0.1/30";
    argv[i++] = "-s"; argv[i++] = "100.24.0.1/30";
    argv[i++] = "-s"; argv[i++] = "100.25.0.1/30";
    argv[i++] = "-s"; argv[i++] = "100.26.0.1/30";
    argv[i++] = "-s"; argv[i++] = "100.27.0.1/30";
    argv[i++] = "-s"; argv[i++] = "100.28.0.1/30";
    argv[i++] = "-s"; argv[i++] = "100.29.0.1/30";
    argv[i++] = "-s"; argv[i++] = "100.30.0.1/30";
    argv[i++] = "-s"; argv[i++] = "100.31.0.1/30";
    argv[i++] = "-s"; argv[i++] = "100.32.0.1/30";
    argv[i++] = NULL;

    assert_failure(argv);
}

/* ---------------- Output format checks ---------------- */

Test(output_format, help_contains_usage) {
    ensure_binary_exists();
    char *const argv[] = { BIN_PATH, "-h", NULL };
    assert_output_contains(argv, "Usage:");
}

Test(output_format, summary_contains_scanning_ranges) {
    ensure_binary_exists();
    require_root_or_skip();
    const char *iface = require_interface_or_skip();
    char *const argv[] = { BIN_PATH, "-i", (char *)iface, "-s", "10.0.2.0/30", NULL };
    assert_output_contains(argv, "Scanning ranges:");
}

Test(output_format, ipv4_output_contains_arp) {
    ensure_binary_exists();
    require_root_or_skip();
    const char *iface = require_interface_or_skip();
    char *const argv[] = { BIN_PATH, "-i", (char *)iface, "-s", "10.0.2.2/32", NULL };
    assert_output_contains(argv, "arp");
}

Test(output_format, ipv4_output_contains_icmpv4) {
    ensure_binary_exists();
    require_root_or_skip();
    const char *iface = require_interface_or_skip();
    char *const argv[] = { BIN_PATH, "-i", (char *)iface, "-s", "10.0.2.2/32", NULL };
    assert_output_contains(argv, "icmpv4");
}

Test(output_format, ipv6_output_contains_ndp) {
    ensure_binary_exists();
    require_root_or_skip();
    const char *iface = require_interface_or_skip();
    char *const argv[] = { BIN_PATH, "-i", (char *)iface, "-s", "fec0::2/128", NULL };
    assert_output_contains(argv, "ndp");
}

Test(output_format, ipv6_output_contains_icmpv6) {
    ensure_binary_exists();
    require_root_or_skip();
    const char *iface = require_interface_or_skip();
    char *const argv[] = { BIN_PATH, "-i", (char *)iface, "-s", "fec0::2/128", NULL };
    assert_output_contains(argv, "icmpv6");
}
