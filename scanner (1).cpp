/*
 * scanner.cpp — Core scanning engine implementation
 * AVADON Network Reconnaissance Framework
 */

#include "../include/scanner.hpp"

#include <algorithm>
#include <arpa/inet.h>
#include <chrono>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <future>
#include <ifaddrs.h>
#include <iomanip>
#include <netdb.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <sstream>
#include <stdexcept>
#include <sys/socket.h>
#include <thread>
#include <unordered_map>
#include <unistd.h>
#include <vector>

// ANSI color codes
#define COLOR_RESET  "\033[0m"
#define COLOR_GREEN  "\033[32m"
#define COLOR_RED    "\033[31m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_CYAN   "\033[36m"
#define COLOR_BOLD   "\033[1m"

// ── Constructor / Destructor ───────────────────────────────
Scanner::Scanner(const ScanConfig& config, Logger& logger)
    : m_config(config), m_logger(logger) {}

Scanner::~Scanner() {
    if (m_raw_sock >= 0) close(m_raw_sock);
}

// ── Privilege + socket init ────────────────────────────────
bool Scanner::init() {
    bool needs_raw = (m_config.mode == "syn"  ||
                      m_config.mode == "udp"  ||
                      m_config.mode == "full" ||
                      m_config.os_detect);

    if (needs_raw) {
        if (geteuid() != 0) {
            m_logger.error("SYN/UDP/OS scan requires root privileges.");
            return false;
        }
        m_raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
        if (m_raw_sock < 0) {
            m_logger.error("Failed to create raw socket: " +
                           std::string(strerror(errno)));
            return false;
        }
        int opt = 1;
        setsockopt(m_raw_sock, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt));
    }
    return true;
}

// ── Target resolution ──────────────────────────────────────
std::vector<std::string> Scanner::resolve_targets() const {
    std::vector<std::string> ips;
    const std::string& t = m_config.target;

    // CIDR notation: e.g. 192.168.1.0/24
    auto slash = t.find('/');
    if (slash != std::string::npos) {
        std::string base = t.substr(0, slash);
        int prefix = std::stoi(t.substr(slash + 1));
        uint32_t mask = prefix > 0 ? (~0u << (32 - prefix)) : 0;
        struct in_addr addr{};
        inet_pton(AF_INET, base.c_str(), &addr);
        uint32_t network = ntohl(addr.s_addr) & mask;
        uint32_t broadcast = network | (~mask);
        for (uint32_t h = network + 1; h < broadcast; ++h) {
            struct in_addr a{};
            a.s_addr = htonl(h);
            char buf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &a, buf, sizeof(buf));
            ips.emplace_back(buf);
        }
        return ips;
    }

    // Single IP or hostname
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(t.c_str(), nullptr, &hints, &res) == 0) {
        for (auto* p = res; p; p = p->ai_next) {
            char buf[INET_ADDRSTRLEN];
            auto* sin = reinterpret_cast<sockaddr_in*>(p->ai_addr);
            inet_ntop(AF_INET, &sin->sin_addr, buf, sizeof(buf));
            ips.emplace_back(buf);
        }
        freeaddrinfo(res);
    }
    return ips;
}

// ── Port range parser ──────────────────────────────────────
std::vector<uint16_t> Scanner::parse_ports() const {
    std::vector<uint16_t> ports;
    std::istringstream ss(m_config.port_range);
    std::string token;

    while (std::getline(ss, token, ',')) {
        auto dash = token.find('-');
        if (dash != std::string::npos) {
            uint16_t start = static_cast<uint16_t>(std::stoi(token.substr(0, dash)));
            uint16_t end   = static_cast<uint16_t>(std::stoi(token.substr(dash + 1)));
            for (uint16_t p = start; p <= end; ++p) ports.push_back(p);
        } else {
            ports.push_back(static_cast<uint16_t>(std::stoi(token)));
        }
    }
    return ports;
}

// ── TCP connect scan ───────────────────────────────────────
PortResult Scanner::tcp_connect_scan(const std::string& ip, uint16_t port) {
    PortResult result;
    result.port     = port;
    result.protocol = "tcp";
    result.service  = map_service(port, "tcp");

    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) { result.state = PortState::UNKNOWN; return result; }

    // Non-blocking
    fcntl(sock, F_SETFL, O_NONBLOCK);

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    auto t_start = std::chrono::steady_clock::now();
    connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr));

    fd_set wset;
    FD_ZERO(&wset);
    FD_SET(sock, &wset);
    struct timeval tv{ 0, static_cast<suseconds_t>(m_config.timeout_ms * 1000) };

    int sel = select(sock + 1, nullptr, &wset, nullptr, &tv);
    auto t_end = std::chrono::steady_clock::now();
    result.latency_us = static_cast<uint32_t>(
        std::chrono::duration_cast<std::chrono::microseconds>(t_end - t_start).count());

    if (sel > 0) {
        int err = 0;
        socklen_t len = sizeof(err);
        getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &len);
        if (err == 0) {
            result.state = PortState::OPEN;
            if (m_config.svc_detect)
                result.banner = grab_banner(ip, port);
        } else {
            result.state = PortState::CLOSED;
        }
    } else {
        result.state = PortState::FILTERED;
    }

    close(sock);
    return result;
}

// ── Banner grabbing ────────────────────────────────────────
std::string Scanner::grab_banner(const std::string& ip, uint16_t port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return "";

    struct timeval tv{ 2, 0 };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    std::string banner;
    if (connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == 0) {
        char buf[256] = {};
        ssize_t n = recv(sock, buf, sizeof(buf) - 1, 0);
        if (n > 0) {
            banner = std::string(buf, n);
            // Strip non-printable chars
            banner.erase(std::remove_if(banner.begin(), banner.end(),
                [](unsigned char c){ return c < 32 && c != '\n' && c != '\r'; }),
                banner.end());
            if (banner.size() > 80) banner = banner.substr(0, 80) + "...";
        }
    }
    close(sock);
    return banner;
}

// ── Reverse DNS ────────────────────────────────────────────
std::string Scanner::reverse_dns(const std::string& ip) const {
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);
    char host[NI_MAXHOST];
    if (getnameinfo(reinterpret_cast<sockaddr*>(&addr), sizeof(addr),
                    host, sizeof(host), nullptr, 0, NI_NAMEREQD) == 0)
        return std::string(host);
    return "";
}

// ── Service name lookup ────────────────────────────────────
std::string Scanner::map_service(uint16_t port, const std::string&) const {
    static const std::unordered_map<uint16_t, std::string> svc = {
        {21,"ftp"},{22,"ssh"},{23,"telnet"},{25,"smtp"},
        {53,"dns"},{80,"http"},{110,"pop3"},{143,"imap"},
        {443,"https"},{445,"smb"},{3306,"mysql"},{3389,"rdp"},
        {5432,"postgresql"},{6379,"redis"},{8080,"http-alt"},
        {8443,"https-alt"},{27017,"mongodb"}
    };
    auto it = svc.find(port);
    return it != svc.end() ? it->second : "unknown";
}

// ── ICMP ping ──────────────────────────────────────────────
bool Scanner::ping_host(const std::string& ip) {
    // Quick TCP connect to port 80 or 443 as fallback ping
    for (uint16_t p : {80, 443, 22}) {
        auto r = tcp_connect_scan(ip, p);
        if (r.state == PortState::OPEN) return true;
    }
    return false;
}

// ── Per-host scan ──────────────────────────────────────────
HostResult Scanner::scan_host(const std::string& ip,
                               const std::vector<uint16_t>& ports) {
    HostResult host;
    host.ip       = ip;
    host.hostname = reverse_dns(ip);
    host.is_up    = true;

    // Thread pool for port scanning
    std::vector<std::future<PortResult>> futures;
    futures.reserve(ports.size());

    size_t idx = 0;
    while (idx < ports.size()) {
        // Batch by thread count
        size_t batch = std::min(static_cast<size_t>(m_config.threads),
                                ports.size() - idx);
        for (size_t i = 0; i < batch; ++i) {
            uint16_t p = ports[idx + i];
            if (m_config.mode == "connect" || m_config.mode == "full") {
                futures.push_back(std::async(std::launch::async,
                    [this, &ip, p]{ return tcp_connect_scan(ip, p); }));
            }
        }
        idx += batch;
    }

    for (auto& f : futures) {
        PortResult pr = f.get();
        if (pr.state == PortState::OPEN) {
            host.ports.push_back(pr);
        }
    }

    // Sort by port number
    std::sort(host.ports.begin(), host.ports.end(),
              [](const PortResult& a, const PortResult& b){
                  return a.port < b.port; });

    return host;
}

// ── Main run loop ──────────────────────────────────────────
ScanResult Scanner::run(volatile sig_atomic_t& g_running) {
    ScanResult result;
    auto t_start = std::chrono::steady_clock::now();

    auto targets = resolve_targets();
    auto ports   = parse_ports();

    if (targets.empty()) {
        m_logger.error("No valid targets resolved from: " + m_config.target);
        return result;
    }

    m_logger.info("Resolved " + std::to_string(targets.size()) + " host(s)");
    m_logger.info("Port range: " + m_config.port_range +
                  " (" + std::to_string(ports.size()) + " ports)");

    result.total_hosts = static_cast<uint32_t>(targets.size());

    for (const auto& ip : targets) {
        if (!g_running) break;

        m_logger.info("Scanning: " + ip);
        HostResult host = scan_host(ip, ports);

        if (!host.ports.empty()) {
            host.is_up = true;
            result.hosts_up++;
            result.open_ports += static_cast<uint32_t>(host.ports.size());
        }
        result.hosts.push_back(host);
    }

    auto t_end = std::chrono::steady_clock::now();
    result.elapsed_sec =
        std::chrono::duration<double>(t_end - t_start).count();

    return result;
}

// ── State string ───────────────────────────────────────────
std::string Scanner::state_str(PortState s) {
    switch (s) {
        case PortState::OPEN:     return "open";
        case PortState::CLOSED:   return "closed";
        case PortState::FILTERED: return "filtered";
        default:                  return "unknown";
    }
}

std::string Scanner::colorize(PortState s, const std::string& text) {
    switch (s) {
        case PortState::OPEN:     return std::string(COLOR_GREEN)  + text + COLOR_RESET;
        case PortState::CLOSED:   return std::string(COLOR_RED)    + text + COLOR_RESET;
        case PortState::FILTERED: return std::string(COLOR_YELLOW) + text + COLOR_RESET;
        default:                  return text;
    }
}

// ── Print results ──────────────────────────────────────────
void Scanner::print_results(const ScanResult& result) const {
    std::cout << "\n" << COLOR_BOLD << COLOR_CYAN
              << "═══════════════════════════════════════════\n"
              << "  AVADON — SCAN RESULTS\n"
              << "═══════════════════════════════════════════\n"
              << COLOR_RESET;

    for (const auto& host : result.hosts) {
        if (host.ports.empty()) continue;

        std::cout << "\n" << COLOR_BOLD << "Host : " << COLOR_CYAN
                  << host.ip << COLOR_RESET;
        if (!host.hostname.empty())
            std::cout << " (" << host.hostname << ")";
        std::cout << "\n";

        std::cout << COLOR_BOLD
                  << std::left
                  << std::setw(8)  << "PORT"
                  << std::setw(12) << "STATE"
                  << std::setw(14) << "SERVICE"
                  << std::setw(10) << "LATENCY"
                  << "BANNER\n"
                  << COLOR_RESET;
        std::cout << std::string(60, '-') << "\n";

        for (const auto& p : host.ports) {
            std::cout << std::left
                      << std::setw(8)  << (std::to_string(p.port) + "/" + p.protocol)
                      << std::setw(12) << colorize(p.state, state_str(p.state))
                      << std::setw(14) << p.service
                      << std::setw(10) << (std::to_string(p.latency_us / 1000) + "ms");
            if (!p.banner.empty())
                std::cout << p.banner;
            std::cout << "\n";
        }
    }

    std::cout << "\n" << COLOR_BOLD << COLOR_CYAN
              << "═══════════════════════════════════════════\n"
              << COLOR_RESET
              << "  Hosts scanned : " << result.total_hosts << "\n"
              << "  Hosts up      : " << result.hosts_up    << "\n"
              << "  Open ports    : " << result.open_ports  << "\n"
              << "  Elapsed       : " << std::fixed << std::setprecision(2)
              << result.elapsed_sec << "s\n"
              << COLOR_BOLD << COLOR_CYAN
              << "═══════════════════════════════════════════\n"
              << COLOR_RESET << "\n";
}

// ── Export results ─────────────────────────────────────────
void Scanner::export_results(const ScanResult& result,
                              const std::string& filepath,
                              const std::string& format) const {
    std::ofstream ofs(filepath);
    if (!ofs) { m_logger.error("Cannot open output file: " + filepath); return; }

    if (format == "json") {
        ofs << "{\n  \"scan_results\": [\n";
        for (size_t i = 0; i < result.hosts.size(); ++i) {
            const auto& h = result.hosts[i];
            if (h.ports.empty()) continue;
            ofs << "    {\n"
                << "      \"ip\": \""       << h.ip       << "\",\n"
                << "      \"hostname\": \"" << h.hostname << "\",\n"
                << "      \"ports\": [\n";
            for (size_t j = 0; j < h.ports.size(); ++j) {
                const auto& p = h.ports[j];
                ofs << "        {\"port\":" << p.port
                    << ",\"state\":\""  << state_str(p.state)
                    << "\",\"service\":\"" << p.service << "\"}";
                if (j + 1 < h.ports.size()) ofs << ",";
                ofs << "\n";
            }
            ofs << "      ]\n    }";
            if (i + 1 < result.hosts.size()) ofs << ",";
            ofs << "\n";
        }
        ofs << "  ]\n}\n";
    } else {
        // Plain text
        ofs << "AVADON Scan Report\n";
        ofs << std::string(40, '=') << "\n";
        for (const auto& h : result.hosts) {
            if (h.ports.empty()) continue;
            ofs << "Host: " << h.ip;
            if (!h.hostname.empty()) ofs << " (" << h.hostname << ")";
            ofs << "\n";
            for (const auto& p : h.ports)
                ofs << "  " << p.port << "/" << p.protocol
                    << "\t" << state_str(p.state)
                    << "\t" << p.service << "\n";
            ofs << "\n";
        }
        ofs << "Total hosts: " << result.total_hosts
            << " | Open ports: " << result.open_ports
            << " | Time: " << result.elapsed_sec << "s\n";
    }
}

// ── TCP SYN scan (stub — requires raw socket, WIP) ─────────
PortResult Scanner::tcp_syn_scan(const std::string& ip, uint16_t port) {
    // TODO: Implement raw SYN packet crafting
    // Fallback to TCP connect scan until raw socket impl is complete
    m_logger.debug("SYN scan not yet implemented, falling back to connect scan");
    return tcp_connect_scan(ip, port);
}

// ── UDP scan (stub — WIP) ──────────────────────────────────
PortResult Scanner::udp_scan(const std::string& ip, uint16_t port) {
    PortResult result;
    result.port     = port;
    result.protocol = "udp";
    result.service  = map_service(port, "udp");

    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) { result.state = PortState::UNKNOWN; return result; }

    struct timeval tv{ 0, static_cast<suseconds_t>(m_config.timeout_ms * 1000) };
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port   = htons(port);
    inet_pton(AF_INET, ip.c_str(), &addr.sin_addr);

    // Send empty UDP datagram
    const char probe[] = "\x00";
    sendto(sock, probe, 1, 0,
           reinterpret_cast<sockaddr*>(&addr), sizeof(addr));

    char buf[64] = {};
    ssize_t n = recv(sock, buf, sizeof(buf) - 1, 0);
    close(sock);

    // If we get a response → open; timeout → open|filtered
    result.state = (n >= 0) ? PortState::OPEN : PortState::FILTERED;
    return result;
}

// ── OS fingerprint (stub — WIP) ────────────────────────────
std::string Scanner::os_fingerprint(const std::string& ip) const {
    // TODO: TTL + TCP window size analysis via raw socket
    // Basic TTL-based guess using ICMP echo
    (void)ip;
    m_logger.debug("OS fingerprinting not yet fully implemented");
    return "unknown";
}
