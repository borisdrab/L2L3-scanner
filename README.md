# IPK project 1 - L2/L3 Network Scanner (Variant Delta)

## Overview

The goal of this project was to implement an L2/L3 network scanner capable of discovering active devices in a network.

- **IPv4 discovery** is performed using ARP
- **IPv6 discovery** is performed using NDP (Neighbor Discovery Protocol)
- **Connectivity checks**:
    - IPv4 -> ICMPv4
    - IPv6 -> ICMPv6

The scanner sends requests and evaluates responses to determine active hosts in given subnets.

---

## Features and Behavior

- Scan one or multiple subnets
- Support both IPv4 and IPv6
- Adjustable timeout (milliseconds)
- Interface listing using `-i`
- Graceful termination using 'Ctrl+C' (SIGINT/SIGTERM)

### Behavior
- Sends ARP/ NDP and ICMP requests to hosts
- Collects responses within the specified timeout window
- Outputs per-host result:
    - L2 reachability (ARP/ NDP)
    - L3 reachability (ICMP)

---


## Usage

### Basic syntax

```bash
sudo ./ipk-L2L3-scan -i INTERFACE [-s SUBNET]... [-w TIMEOUT]
```

## Examples

### Scan multiple IPv4 subnets
```bash
sudo ./ipk-L2L3-scan -i enp0s1 -w 2000 -s 192.168.0.0/24 -s 10.0.0.0/28
```

### Scan IPv6 subnet
```bash
sudo ./ipk-L2L3-scan -i enp0s1 -w 1500 -s fcd::/120
```

### Show help
• Short version
```bash
./ipk-L2L3-scan -h
```

• Full version
```bash
./ipk-L2L3-scan --help
```

### List available interfaces
```bash
./ipk-L2L3-scan -i
```

## Build
Build the project:
```bash
make
```

### Clean build
```bash
make clean
```

### Development environment
```bash
make NixDevShellName
```

### Run automated tests
(Tests in C, used Criterion framework)
```bash
make test
```

### Package submission
```bash
make pack
```


## Implementation Notes
- ARP, NDP, ICMPv4 were implemented manually (based on standards):

    - packet/ header construction

    - checksum calculation

    - raw socket communication

- ICMPv6:

    - implemented using kernel-assisted approach. This approach was adopted during development after discussion with classmates.

- The project uses:

    - raw sockets(AF_PACKET, SOCK_RAW)

    - gettimeofday() for timeout handling  

Every big change/ improvement was versioned in a Gitea repository.


## Design Decisions
Originally, the scanner had performance issues due to inefficient evaluation. The program was sending a request to one host and then waiting for the whole timeout interval before moving to the next one. If the host did not respond, it still waited which made the scanning very slow. The total time was basically (timeout x number of hosts).

Through time I decided to change the logic (lifecycle) of program to sending requests individually to hosts and collecting their responses grouply (batchly) in order to improve the speed of evaluating. The logic was divided into three phases: opening, sending and receiving.

I was concerning multithreading approach but I wasnt really confident to rework it that way because it would increase the complexity and potential issues. I decided not to pursue this approach. Instead, I choose a simpler hybrid solution that achieves improvement while keeping the implementation manageable.

After the first dry run evaluation (51-100% efficiency range),  I focused mainly on reworking the lifecycle rather than introducing major structural changes. The final version contains improved evaluation logic, better performance, and cleaner code.


## Known Limitations
• Maximum number of generated hosts is limited (65 536)

• Requires root privileges (raw sockets)

• No parallel scanning (single-threaded design)

• Not optimized for very large networks (e.g. /16 and larger)


## Possible Improvements
• Multithreading/ async scanning for more efficiency

• Better rate limiting

• Smarter timeout handling 

• More advanced filtering of scanned ranges


## Testing
The project was tested in multiple ways:

• on the provided virtual machine

• in a custom virtual network created using venv-dev

• by manual testing

• by automated tests written in C using the Criterion framework (recommended in "Issues" on the Gitea by academic workers)

Automated tests can be executed using:
```bash
make test
```

Some tests may be skipped with the message:
```bash
[SKIP] requires root
```
This is expected behavior. Certain tests (e.g., ARP, ICMP, NDP scanning) require raw socket access, which is restricted to privileged users.

### Running full test suite

To run all tests, including integration and network-related tests, use:
```bash
sudo -E make test
```
The -E flag preserves the environment (required for Nix-based development environments where Criterion is provided via /nix/store).

The testing strategy combines both validation-oriented and integration testing.

- Argument validation tests verify correct handling of CLI parameters, including invalid inputs and edge cases.
- Integration tests execute the full scanner workflow, ensuring correct interaction between modules (ARP, NDP, ICMPv4, ICMPv6).
- Packet sending and receiving is tested indirectly through real execution of the scanner on a network interface.

Low-level packet structure (e.g. exact binary format of frames) is not tested separately, but correctness is verified through successful communication and expected outputs.

### What was tested 

• IPv4 scanning (ARP + ICMPv4)

• IPv6 scanning (NDP + ICMPv6)

• Multiple subnets

• Timeout-related behavior

• Argument validation

• Interrupt handling (Ctrl+C)

• Unsupported or invalid input formats

• Various edge cases

### Why it was tested
These tests were chosen to verify both the common use cases and edge cases required by the assignment. Special attention was given to argument parsing, subnet validation, and correct behavior for both IPv4 and IPv6.

### How it was tested

Testing was performed using a combination of:

• Automated tests written in C using the Criterion framework

• Manual testing on real and virtual networks

• Integration testing by executing the scanner with various parameters

Tests were executed both with and without root privileges to verify correct behavior and expected limitations.

### Testing environment
The main testing environment was the provided reference virtual machine running Linux in the faculty Nix development environment. Additional tests were performed in a custom virtual environment with configured virtual interfaces and hosts.

### Example Test Case
Command:
```bash
sudo ./ipk-L2L3-scan -i enp0s1 -s 10.0.2.0/30
```

### Expected output 
• Program prints scanning ranges

• Outputs ARP and ICMP results for each host

### Actual output
```bash
Scanning ranges:
10.0.2.0/30 2

10.0.2.1 arp FAIL, icmpv4 FAIL
10.0.2.2 arp FAIL, icmpv4 FAIL
```

## Expected and actual results
For valid inputs, the scanner was expected to start correctly, print normalized scanned ranges, and output ARP/ NDP and ICMP results for individual hosts.

For invalid inputs, the scanner was expected to terminate with an error.


## LLM Usage
LLM tools were used for:

• Understanding networking concepts and system libraries needed for development

• Refining implementation details

• __Converting an earlier Bash-based testing approach created by me into Criterion-based C tests, following recommendations in the IPK Issues discussion__

• Debugging and code review assistance

All core implementation decisions and logic were created independently.


## Author
Boris Nicolas Dráb

FIT VUT Brno


## References
• Linux networking documentation:
  https://docs.kernel.org/networking/index.html

• Veth virtual network interfaces:
  https://man7.org/linux/man-pages/man4/veth.4.html

• Criterion testing framework:
  https://github.com/Snaipe/Criterion

• IPK Gitea Issues discussions