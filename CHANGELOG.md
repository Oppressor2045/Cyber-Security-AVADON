# Changelog

All notable changes to AVADON will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [1.0.0] — 2025-01-01

### Added
- Initial release of AVADON Network Reconnaissance Framework
- TCP connect scan via non-blocking `connect()` + `select()`
- Multithreaded port scanning using `std::async` (default: 100 threads)
- CIDR subnet expansion (e.g. `192.168.1.0/24` → 254 hosts)
- Port range parser supporting list (`22,80,443`) and range (`1-1024`) syntax
- Service banner grabbing (`--svc` flag)
- Reverse DNS resolution per host
- Port-to-service name mapping (ssh, http, https, mysql, rdp, etc.)
- JSON and TXT result export (`-o`, `-f` flags)
- ANSI color terminal output (open=green, filtered=yellow, closed=red)
- Graceful shutdown via `SIGINT` / `SIGTERM` signal handling
- CLI argument parser with full flag support (`-t`, `-p`, `-m`, `-T`, `--os`, `--svc`, `-s`, `-v`)
- Logger with INFO / WARN / ERROR / DEBUG levels and file output
- ASCII art banner with version and author info
- `CMakeLists.txt` build system (C++17, Release/Debug targets)
- MIT License

### Known Limitations
- SYN scan (`-m syn`) falls back to TCP connect scan (raw socket WIP)
- OS fingerprinting (`--os`) returns `unknown` (TTL analysis WIP)
- UDP scan is basic probe only (ICMP unreachable parsing WIP)
- IPv6 not supported

---

## [Unreleased]

### Planned
- `feat` Raw socket SYN scan implementation
- `feat` OS fingerprinting via TTL + TCP window size analysis
- `feat` Full UDP scan with ICMP unreachable handling
- `feat` XML export format (Nmap-compatible)
- `feat` IPv6 support
- `feat` Top-N common ports preset (e.g. `--top 100`)
- `feat` Lua scripting engine for custom probes
- `fix`  ICMP ping sweep (replace TCP fallback)
- `docs` Scan result screenshots in README
- `ci`   GitHub Actions CI/CD workflow

---

## Version History

| Version | Date       | Description              |
|---------|------------|--------------------------|
| 1.0.0   | 2025-01-01 | Initial release          |
| —       | Unreleased | SYN scan · OS detection  |
