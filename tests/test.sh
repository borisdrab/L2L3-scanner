#!/usr/bin/env bash
set -u
set -o pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
BIN="$PROJECT_DIR/ipk-L2L3-scan"
 
INTERFACE=${INTERFACE:-$(ls /sys/class/net | grep -E '^(e|w)' | head -n1)}  #dynamically choose network interface

pass_count=0
fail_count=0

IS_ROOT=0
if [ "$(id -u)" -eq 0 ]; then
    IS_ROOT=1
fi


run_root_test() {
    local test_name="$1"
    shift

    if [ "$IS_ROOT" -ne 1 ]; then
        echo "------------------------------------"
        echo "TEST: $test_name"
        echo "Command: $*"
        echo "------------------------------------"
        echo "RESULT: SKIPPED (requires root)"
        echo
        return
    fi

    run_test "$test_name" "$@"
}

check_root_output_contains() {
    local test_name="$1"
    local expected="$2"
    shift 2

    if [ "$IS_ROOT" -ne 1 ]; then
        echo "----------------"
        echo "TEST: $test_name"
        echo "Command: $*"
        echo "Expected substring: $expected"
        echo "----------------"
        echo "RESULT : SKIPPED (requires root)"
        echo
        return
    fi

    check_output_contains "$test_name" "$expected" "$@"
}


if [ ! -x "$BIN" ]; then
    echo "Error: binary '$BIN' not found or not executable"
    exit 1
fi

run_test(){
    local test_name="$1"
    shift

    echo "------------------------------------"
    echo "TEST: $test_name"
    echo "Command: $*"
    echo "------------------------------------"

    "$@"
    local exit_code=$?

    echo "------------------------------------"
    echo "EXIT CODE: $exit_code"

    if [ $exit_code -eq 0 ]; then
        echo "RESULT : PASS"
        pass_count=$((pass_count+1))
    else
        echo "RESULT : FAIL"
        fail_count=$((fail_count+1))
    fi

    echo
    
}

run_expected_fail() {
    local test_name="$1"
    shift 

    echo "------------------------------------"
    echo "TEST: $test_name"
    echo "Command: $*"
    echo "------------------------------------"

    "$@"
    local exit_code=$?

    echo "------------------------------------"
    echo "EXIT CODE: $exit_code"

    if [ $exit_code -ne 0 ]; then
        echo "RESULT : PASS (expected failure)"
        pass_count=$((pass_count+1))
    else
        echo "RESULT : FAIL (unexpected success)"
        fail_count=$((fail_count+1))
    fi

    echo


}

check_output_contains() {
    local test_name="$1"
    local expected="$2"
    shift 2

    echo "----------------"
    echo "TEST: $test_name"
    echo "Command: $*"
    echo "Expected substring: $expected"
    echo "----------------"

    local output
    output=$("$@" 2>&1)
    local exit_code=$?

    echo "$output"
    echo "----------------"
    echo "EXIT CODE: $exit_code"

    if [ $exit_code -eq 0 ] && echo "$output" | grep -Fq "$expected"; then
        echo "RESULT : PASS"
        pass_count=$((pass_count+1))
    else
        echo "RESULT : FAIL"
        fail_count=$((fail_count+1))
    fi

    echo
}

echo
echo "Running IPK L2/L3 scanner tests ...."
echo

# Basic CLI tests
run_test "help short" "$BIN" -h
run_test "help long" "$BIN" --help
run_test "interface list" "$BIN" -i

# Argument Validation tests
run_expected_fail "missing argument" "$BIN"
run_expected_fail "missing interface" "$BIN" -s 10.10.0.0/30
run_expected_fail "missing subnet after -s" "$BIN" -i "$INTERFACE" -s
run_expected_fail "missing timeout after -w" "$BIN" -i "$INTERFACE" -w 
run_expected_fail "invalid timeout zero" "$BIN" -i "$INTERFACE" -w 0 -s 10.0.2.0/30
run_expected_fail "invalid timeout negative" "$BIN" -i "$INTERFACE" -w -5 -s 10.0.2.0/30
run_expected_fail "invalid timeout text" "$BIN" -i "$INTERFACE" -w ipkipk -s 10.0.2.0/30
run_expected_fail "invalid timeout too large" "$BIN" -i "$INTERFACE" -w 800008 -s 10.0.2.0/30

run_expected_fail "invalid subnet text" "$BIN" -i "$INTERFACE" -s ooooooo00ooooo
run_expected_fail "invalid ipv4 subnet" "$BIN" -i "$INTERFACE" -s 10.10.0.999/30
run_expected_fail "invalid ipv6 subnet" "$BIN" -i "$INTERFACE" -s fd00::gg/126
run_expected_fail "invalid ipv4 prefix" "$BIN" -i "$INTERFACE" -s 10.10.0.0/33
run_expected_fail "invalid ipv6 prefix" "$BIN" -i "$INTERFACE" -s fd00::/129
run_expected_fail "subnet missing prefix ipv4" "$BIN" -i "$INTERFACE" -s 10.0.0.6
run_expected_fail "subnet missing prefix ipv6" "$BIN" -i "$INTERFACE" -s fec0::6

run_expected_fail "nonexistent interface" "$BIN" -i neexistuje -s 10.10.0.0/30
run_expected_fail "unknown argument" "$BIN" --xdxdxdxdxd

run_expected_fail "empty interface string" "$BIN" -i "" -s 10.0.2.0/30
run_expected_fail "empty subnet string" "$BIN" -i "$INTERFACE" -s ""
run_expected_fail "empty timout string" "$BIN" -i "$INTERFACE" -w "" -s 10.0.0.0/30

run_expected_fail "extra stray argument after subnet" "$BIN" -i "$INTERFACE" -s 10.1.1.1/30 extra
run_expected_fail "extra stray argument after interface" "$BIN" -i "$INTERFACE" extra -s 10.1.1.1/30

run_expected_fail "missing subnet but interface present" "$BIN" -i "$INTERFACE"


# Repeated arguments
run_root_test "duplicated interface - last wins" "$BIN" -i lo -i "$INTERFACE" -s 10.2.5.0/30
run_root_test "duplicated timeout - last wins" "$BIN" -i "$INTERFACE" -w 1 -w 1000 -s 10.1.1.1/30

# ipv4 edge cases
run_root_test "ipv4 /32 single host" "$BIN" -i "$INTERFACE" -s 10.0.2.2/32
run_root_test "ipv4 /31 special case" "$BIN" -i "$INTERFACE" -s 10.0.2.0/31
run_root_test "ipv4 /29 small range" "$BIN" -i "$INTERFACE" -s 10.0.3.0/29

# ipv6 edge cases
run_root_test "ipv6 /128 single host" "$BIN" -i "$INTERFACE" -s fec0::2/128
run_root_test "ipv6 normalized /126" "$BIN" -i "$INTERFACE" -s fec0::1/126



# Multiple subnets
run_root_test "multiple subnets ipv4+ipv6" "$BIN" -i "$INTERFACE" -s 10.0.2.0/30 -s fec0::2/128
run_root_test "duplicated ipv4 subnet normalized" "$BIN" -i "$INTERFACE" -s 10.0.2.0/30 -s 10.0.2.1/30
run_root_test "duplicated ipv6 subnet" "$BIN" -i "$INTERFACE" -s fec0::2/128 -s fec0::8/128
run_root_test "multiple subnets 3x" "$BIN" -i "$INTERFACE" -s 100.9.6.7/30 -s 67.67.67.67/30 -s fec3::ff/128


# Integration tests requiring raw sockets
run_root_test "ipv4 /30 scan (sudo)" "$BIN" -i "$INTERFACE" -s 10.0.2.0/30
run_root_test "ipv4 /32 scan (sudo)" "$BIN" -i "$INTERFACE" -s 10.0.2.2/32
run_root_test "ipv6 /128 scan (sudo)" "$BIN" -i "$INTERFACE" -s fec0::2/128

run_root_test "random order args" "$BIN" -s 172.16.5.0/30 -i enp0s1 
run_expected_fail "too many subnets" "$BIN" -i enp0s1 \
-s 100.0.0.1/30 \
-s 100.1.0.1/30 \
-s 100.2.0.1/30 \
-s 100.3.0.1/30 \
-s 100.4.0.1/30 \
-s 100.5.0.1/30 \
-s 100.6.0.1/30 \
-s 100.7.0.1/30 \
-s 100.8.0.1/30 \
-s 100.9.0.1/30 \
-s 100.10.0.1/30 \
-s 100.11.0.1/30 \
-s 100.12.0.1/30 \
-s 100.13.0.1/30 \
-s 100.14.0.1/30 \
-s 100.15.0.1/30 \
-s 100.16.0.1/30 \
-s 100.17.0.1/30 \
-s 100.18.0.1/30 \
-s 100.19.0.1/30 \
-s 100.20.0.1/30 \
-s 100.21.0.1/30 \
-s 100.22.0.1/30 \
-s 100.23.0.1/30 \
-s 100.24.0.1/30 \
-s 100.25.0.1/30 \
-s 100.26.0.1/30 \
-s 100.27.0.1/30 \
-s 100.28.0.1/30 \
-s 100.29.0.1/30 \
-s 100.30.0.1/30 \
-s 100.31.0.1/30 \
-s 100.32.0.1/30


# Output-format checks
check_output_contains "help contains Usage" "Usage:" "$BIN" -h
check_root_output_contains "summary contains Scanning ranges" "Scanning ranges:" "$BIN" -i "$INTERFACE" -s 10.0.2.0/30
check_root_output_contains "ipv4 output contains arp" "arp" "$BIN" -i "$INTERFACE" -s 10.0.2.2/32
check_root_output_contains "ipv4 output contains icmpv4" "icmpv4" "$BIN" -i "$INTERFACE" -s 10.0.2.2/32
check_root_output_contains "ipv6 output contains ndp" "ndp" "$BIN" -i "$INTERFACE" -s fec0::2/128
check_root_output_contains "ipv6 output contains icmpv6" "icmpv6" "$BIN" -i "$INTERFACE" -s fec0::2/128

echo "------------------------------------"
echo "SUMMARY"
echo "PASSED: $pass_count"
echo "FAILED: $fail_count"
echo "------------------------------------"

if [ $fail_count -ne 0 ]; then
    exit 1
fi

exit 0
