#pragma once

/*
 * argparser.hpp — CLI argument parser
 * AVADON Network Reconnaissance Framework
 */

#include <string>
#include <iostream>
#include <cstdlib>

class ArgParser {
public:
    ArgParser(int argc, char* argv[]) : m_argc(argc), m_argv(argv) {}

    bool parse() {
        if (m_argc < 2) return false;
        for (int i = 1; i < m_argc; ++i) {
            std::string arg = m_argv[i];
            if (arg == "-h" || arg == "--help")   { m_help    = true; return true; }
            if (arg == "-v" || arg == "--verbose") { m_verbose = true; continue; }
            if (arg == "-s" || arg == "--stealth") { m_stealth = true; continue; }
            if (arg == "--os")                     { m_os      = true; continue; }
            if (arg == "--svc")                    { m_svc     = true; continue; }
            if ((arg == "-t" || arg == "--target") && i+1 < m_argc)
                { m_target = m_argv[++i]; continue; }
            if ((arg == "-p" || arg == "--ports")  && i+1 < m_argc)
                { m_ports  = m_argv[++i]; continue; }
            if ((arg == "-m" || arg == "--mode")   && i+1 < m_argc)
                { m_mode   = m_argv[++i]; continue; }
            if ((arg == "-T" || arg == "--threads")&& i+1 < m_argc)
                { m_threads = std::stoi(m_argv[++i]); continue; }
            if ((arg == "--timeout")               && i+1 < m_argc)
                { m_timeout = std::stoi(m_argv[++i]); continue; }
            if ((arg == "-o" || arg == "--output") && i+1 < m_argc)
                { m_output = m_argv[++i]; continue; }
            if ((arg == "-f" || arg == "--format") && i+1 < m_argc)
                { m_format = m_argv[++i]; continue; }
            // Positional: first unknown arg = target
            if (m_target.empty() && arg[0] != '-')
                { m_target = arg; continue; }
        }
        return !m_target.empty() || m_help;
    }

    void usage(const char* prog) const {
        std::cout <<
            "\nUsage: " << prog << " [OPTIONS] <target>\n\n"
            "  target              IP, hostname, or CIDR (e.g. 192.168.1.0/24)\n\n"
            "Options:\n"
            "  -t, --target <ip>   Target specification\n"
            "  -p, --ports  <range>Port range  (default: 1-1024)\n"
            "                      Examples: 22,80,443  |  1-65535  |  top100\n"
            "  -m, --mode   <mode> Scan mode: connect (default) | syn | udp | ping | full\n"
            "  -T, --threads <n>   Thread count (default: 100)\n"
            "      --timeout <ms>  Per-port timeout in ms (default: 1000)\n"
            "      --os            Enable OS fingerprinting (root)\n"
            "      --svc           Enable service/banner grabbing\n"
            "  -s, --stealth       Stealth mode (slower, less noise)\n"
            "  -o, --output <file> Save results to file\n"
            "  -f, --format <fmt>  Output format: txt (default) | json\n"
            "  -v, --verbose       Verbose logging\n"
            "  -h, --help          Show this help\n\n"
            "Examples:\n"
            "  " << prog << " 192.168.1.1\n"
            "  " << prog << " -t 10.0.0.0/24 -p 22,80,443 --svc -o results.json -f json\n"
            "  " << prog << " -t scanme.nmap.org -m connect -p 1-1024 -T 200 -v\n\n";
    }

    bool        show_help()       const { return m_help;    }
    bool        is_verbose()      const { return m_verbose; }
    bool        is_stealth()      const { return m_stealth; }
    bool        detect_os()       const { return m_os;      }
    bool        detect_services() const { return m_svc;     }
    std::string get_target()      const { return m_target;  }
    std::string get_port_range()  const { return m_ports;   }
    std::string get_mode()        const { return m_mode;    }
    std::string get_output_file() const { return m_output;  }
    std::string get_output_format() const { return m_format;}
    uint32_t    get_timeout()     const { return m_timeout; }
    uint32_t    get_threads()     const { return static_cast<uint32_t>(m_threads); }

private:
    int         m_argc;
    char**      m_argv;
    bool        m_help    = false;
    bool        m_verbose = false;
    bool        m_stealth = false;
    bool        m_os      = false;
    bool        m_svc     = false;
    std::string m_target;
    std::string m_ports   = "1-1024";
    std::string m_mode    = "connect";
    std::string m_output;
    std::string m_format  = "txt";
    int         m_threads = 100;
    uint32_t    m_timeout = 1000;
};
