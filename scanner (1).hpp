#pragma once

/*
 * scanner.hpp — Core scanning engine
 * AVADON Network Reconnaissance Framework
 */

#include <csignal>
#include <string>
#include <vector>
#include <atomic>
#include <cstdint>
#include "logger.hpp"

// ── Port state ─────────────────────────────────────────────
enum class PortState {
    OPEN,
    CLOSED,
    FILTERED,
    UNKNOWN
};

// ── Scan modes ─────────────────────────────────────────────
enum class ScanMode {
    TCP_CONNECT,   // Full TCP handshake (no root required)
    TCP_SYN,       // Half-open SYN scan (root required)
    UDP,           // UDP scan (root required)
    PING,          // ICMP ping sweep
    FULL           // TCP_SYN + UDP + OS + Service detection
};

// ── Port result ────────────────────────────────────────────
struct PortResult {
    uint16_t    port;
    PortState   state;
    std::string protocol;   // "tcp" | "udp"
    std::string service;    // e.g. "ssh", "http", "unknown"
    std::string banner;     // raw service banner if grabbed
    uint32_t    latency_us; // response latency in microseconds
};

// ── Host result ────────────────────────────────────────────
struct HostResult {
    std::string              ip;
    std::string              hostname;    // reverse DNS
    std::string              os_guess;   // OS fingerprint guess
    std::string              mac;        // MAC address (LAN only)
    bool                     is_up;
    std::vector<PortResult>  ports;
};

// ── Aggregate scan result ──────────────────────────────────
struct ScanResult {
    std::vector<HostResult> hosts;
    uint32_t total_hosts = 0;
    uint32_t hosts_up    = 0;
    uint32_t open_ports  = 0;
    double   elapsed_sec = 0.0;
};

// ── Scan configuration ─────────────────────────────────────
struct ScanConfig {
    std::string target;         // IP, CIDR, or hostname
    std::string port_range;     // e.g. "1-1024", "80,443,8080"
    std::string mode;           // "syn", "connect", "udp", "ping", "full"
    uint32_t    timeout_ms = 1000;
    uint32_t    threads    = 100;
    bool        stealth    = false;
    bool        os_detect  = false;
    bool        svc_detect = false;
};

// ── Scanner class ──────────────────────────────────────────
class Scanner {
public:
    explicit Scanner(const ScanConfig& config, Logger& logger);
    ~Scanner();

    // Initialize raw socket / privilege check
    bool init();

    // Run the scan; g_running lets caller interrupt via signal
    ScanResult run(volatile sig_atomic_t& g_running);

    // Output helpers
    void print_results(const ScanResult& result) const;
    void export_results(const ScanResult& result,
                        const std::string& filepath,
                        const std::string& format) const; // "txt" | "json" | "xml"

private:
    ScanConfig  m_config;
    Logger&     m_logger;
    int         m_raw_sock = -1;

    // Resolve target string → list of IPs
    std::vector<std::string> resolve_targets() const;

    // Parse port range string → list of port numbers
    std::vector<uint16_t> parse_ports() const;

    // Per-host scan dispatch
    HostResult scan_host(const std::string& ip,
                         const std::vector<uint16_t>& ports);

    // Low-level scan methods
    PortResult tcp_connect_scan(const std::string& ip, uint16_t port);
    PortResult tcp_syn_scan   (const std::string& ip, uint16_t port);
    PortResult udp_scan       (const std::string& ip, uint16_t port);

    // Auxiliary
    bool        ping_host     (const std::string& ip);
    std::string grab_banner   (const std::string& ip, uint16_t port);
    std::string reverse_dns   (const std::string& ip) const;
    std::string os_fingerprint(const std::string& ip) const;
    std::string map_service   (uint16_t port, const std::string& proto) const;

    // Output formatting
    static std::string state_str(PortState s);
    static std::string colorize (PortState s, const std::string& text);
};
