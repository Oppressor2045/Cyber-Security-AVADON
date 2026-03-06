<!--
  AVADON — Network Reconnaissance Framework
  Author: Oppressor2045
-->

<div align="center">

**Network Reconnaissance Framework**

![Language](https://img.shields.io/badge/Language-C%2B%2B17-0a0f2e?style=for-the-badge&logo=cplusplus&logoColor=4488ff)
![Platform](https://img.shields.io/badge/Platform-Kali_Linux-0a0f2e?style=for-the-badge&logo=kalilinux&logoColor=557fff)
![Version](https://img.shields.io/badge/Version-1.0.0-0a0f2e?style=for-the-badge&logoColor=4488ff)
[![License](https://img.shields.io/badge/License-MIT-0a0f2e?style=for-the-badge&logoColor=4488ff)](./LICENSE)

</div>

---

> ⚠️ **LEGAL DISCLAIMER**
> This tool is intended for **authorized security testing and educational purposes only.**
> Unauthorized use against systems you do not own or have explicit permission to test is **illegal.**
> The author assumes **no liability** for misuse.

---

## Overview

**AVADON** is a lightweight, multithreaded network reconnaissance tool written in **C++17**, designed to run natively on Kali Linux. It supports TCP connect scans, service banner grabbing, reverse DNS resolution, and JSON/text report export — all from a clean CLI interface.

Built as an educational alternative to Nmap to understand how port scanners work at the socket level.

---

## Features

| Feature | Status |
|---------|--------|
| TCP Connect Scan | ✅ |
| Multithreaded scanning | ✅ |
| Port range / list parser | ✅ |
| CIDR target expansion | ✅ |
| Service banner grabbing | ✅ |
| Reverse DNS resolution | ✅ |
| JSON / TXT export | ✅ |
| Verbose logging | ✅ |
| SYN scan (raw socket) | 🔧 WIP |
| OS fingerprinting | 🔧 WIP |
| UDP scan | 🔧 WIP |

---

## Build

### Requirements
- Kali Linux / Debian-based distro
- `g++` with C++17 support
- `cmake >= 3.16`

```bash
# Clone
git clone https://github.com/Oppressor2045/AVADON.git
cd AVADON

# Build
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j$(nproc)

# Install (optional)
sudo make install
```

---

## Usage

```bash
# Basic scan (top 1024 ports)
./avadon 192.168.1.1

# Scan specific ports with banner grabbing
./avadon -t 192.168.1.1 -p 22,80,443,8080 --svc

# CIDR subnet scan
./avadon -t 192.168.1.0/24 -p 1-1024 -T 200

# Export to JSON
./avadon -t 10.0.0.1 -p 1-65535 -o report -f json

# Verbose mode
./avadon -t scanme.nmap.org -p 1-1024 -v
```

### Options

```
  -t, --target <ip>     IP, hostname, or CIDR
  -p, --ports  <range>  Port range: 22,80,443 | 1-1024 | 1-65535
  -m, --mode   <mode>   connect (default) | syn | ping | full
  -T, --threads <n>     Thread count (default: 100)
      --timeout <ms>    Per-port timeout ms (default: 1000)
      --svc             Enable service/banner grabbing
      --os              Enable OS fingerprinting (root)
  -s, --stealth         Stealth mode
  -o, --output <file>   Save results to file
  -f, --format <fmt>    txt (default) | json
  -v, --verbose         Verbose logging
  -h, --help            Help
```

---

## Output Example

```
[12:34:01] [INFO ] AVADON v1.0.0 initialized
[12:34:01] [INFO ] Target  : 192.168.1.1
[12:34:01] [INFO ] Resolved 1 host(s)
[12:34:01] [INFO ] Port range: 1-1024 (1024 ports)

═══════════════════════════════════════════
  AVADON — SCAN RESULTS
═══════════════════════════════════════════

Host : 192.168.1.1 (router.local)

PORT     STATE        SERVICE       LATENCY   BANNER
------------------------------------------------------------
22/tcp   open         ssh           2ms       SSH-2.0-OpenSSH_8.9
80/tcp   open         http          1ms
443/tcp  open         https         1ms

═══════════════════════════════════════════
  Hosts scanned : 1
  Hosts up      : 1
  Open ports    : 3
  Elapsed       : 1.24s
═══════════════════════════════════════════
```

---

## Project Structure

```
AVADON/
├── CMakeLists.txt
├── README.md
├── include/
│   ├── scanner.hpp
│   ├── argparser.hpp
│   ├── logger.hpp
│   └── banner.hpp
└── src/
    ├── main.cpp
    └── scanner.cpp
```

---

## File Reference

### `src/main.cpp`
프로그램 진입점. 시그널 핸들러(`SIGINT`, `SIGTERM`) 등록, CLI 인자 파싱, Logger 초기화, `ScanConfig` 구성 후 `Scanner::run()` 호출까지의 전체 실행 흐름을 담당한다. 스캔 완료 후 결과 출력 및 파일 저장을 트리거한다.

### `src/scanner.cpp`
AVADON의 핵심 엔진. 주요 구현 내용:

| 메서드 | 역할 |
|--------|------|
| `init()` | raw 소켓 생성 및 root 권한 확인 |
| `resolve_targets()` | CIDR / 호스트명 → IP 목록 변환 |
| `parse_ports()` | `"22,80,1-1024"` 형태 포트 문자열 파싱 |
| `tcp_connect_scan()` | Non-blocking `connect()` + `select()` 기반 포트 상태 판별 |
| `grab_banner()` | 오픈 포트에 접속해 서비스 배너 수집 |
| `reverse_dns()` | IP → 호스트명 역방향 DNS 조회 |
| `map_service()` | 포트 번호 → 서비스명 매핑 (ssh, http 등) |
| `scan_host()` | `std::async` 기반 멀티스레드 포트 스캔 |
| `run()` | 전체 타겟 순회, 결과 집계, 경과 시간 측정 |
| `print_results()` | ANSI 컬러 터미널 출력 |
| `export_results()` | JSON / TXT 파일 저장 |

### `include/scanner.hpp`
스캐너 인터페이스 정의. `PortState` / `ScanMode` enum, `PortResult` / `HostResult` / `ScanResult` / `ScanConfig` 구조체, `Scanner` 클래스 선언을 포함한다.

```
PortResult   — 단일 포트 스캔 결과 (상태, 서비스명, 배너, 레이턴시)
HostResult   — 단일 호스트 스캔 결과 (IP, 호스트명, 포트 목록)
ScanResult   — 전체 스캔 집계 (호스트 목록, 오픈 포트 수, 소요 시간)
ScanConfig   — 스캔 옵션 (타겟, 포트 범위, 모드, 스레드 수, 타임아웃 등)
```

### `include/argparser.hpp`
외부 라이브러리 없이 직접 구현한 CLI 파서. `argc` / `argv` 를 순회하며 플래그(`-v`, `-s`)와 키-값 인자(`-t`, `-p`, `-m` 등)를 파싱한다. 파싱 실패 시 `usage()` 출력 후 종료한다.

### `include/logger.hpp`
타임스탬프 + 레벨 기반 로거. `INFO` / `WARN` / `ERROR` / `DEBUG` 4단계를 지원하며, ANSI 색상으로 터미널 출력과 동시에 로그 파일(`-o` 옵션 지정 시)에 기록한다. `--verbose` 플래그가 없으면 `DEBUG` 레벨은 출력되지 않는다.

### `include/banner.hpp`
실행 시 터미널에 출력되는 ASCII 아트 배너. 툴 이름, 버전, 제작자, 법적 고지를 포함한다.

### `CMakeLists.txt`
CMake 빌드 스크립트. C++17 표준, `Release` / `Debug` 플래그, `Threads` 링크, 설치 타겟을 정의한다.

---

## Roadmap

- [ ] SYN scan via raw sockets
- [ ] UDP scan
- [ ] OS fingerprinting (TTL + TCP window analysis)
- [ ] XML export (Nmap-compatible)
- [ ] Lua scripting engine for custom probes
- [ ] IPv6 support

---

## Author

**Oppressor2045** — Cyber Security

---

*For educational and authorized testing use only.*
