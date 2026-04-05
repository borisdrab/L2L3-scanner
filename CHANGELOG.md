# Changelog

All notable changes to this project are documented here.

Changes are listed from oldest (bottom) to newest (top).

This changelog reflects the development progression of the project from initial skeleton to final optimized implementation.

----

## / Final Version /

### Added
- Final README documentation
- CHANGELOG file
- Automated tests written in C using the Criterion framework

### Changed
- Reworked scanning lifecycle from sequential host-by-host waiting to batched sending and receiving
- Improved overall scan performance
- Refactored parts of scanning logic in ARP, NDP, ICMPv4 and ICMPv6 related modules
- Replaced the original shell-based testing approach with Criterion-based tests

### Fixed
- Argument validation edge cases
- Subnet parsing and normalization issues
- Stability problems discovered during later testing
- Fixed MAC address formatting

## Known Limitations
- Maximum number of generated hosts is limited (65 536)
- Requires root privileges (raw sockets)
- No parallel scanning (single-threaded design)
- Not optimized for very large networks (e.g. /16 and larger)

----

## / Feature Completion Phase /

### Added
- NDP module for IPv6 discovery
- ICMPv6 support 
- Additional header files and source modules for IPv6-related functionality
- Shell-based test suite (`test.sh`)

### Changed
- Extended scanner from IPv4-only behavior to both IPv4 and IPv6

----

## / Core IPv4 Phase /

### Added
- ARP module for IPv4 discovery
- ICMPv4 support
- Required header files and corresponding source files
- Initial Makefile for building the project

### Changed
- Expanded the project from argument/subnet parsing to actual host scanning

----

## / Parsing and Validation Phase /

### Added
- CLI argument parsing
- Interface handling
- Subnet parser
- Subnet host counting
- Subnet normalization and validation logic

### Fixed
- Handling of invalid prefixes and incorrect subnet input

----

## / Initial Version /

### Added
- Initial project skeleton and directory structure
- Main program entry point (`main.c`)
- Basic header/source file organization
