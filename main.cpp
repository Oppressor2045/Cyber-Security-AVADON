/*
 * ═══════════════════════════════════════════════════════════
 *  AVADON — Network Reconnaissance Framework
 *  Author  : Oppressor2045
 *  Version : 1.0.0
 *  License : MIT
 *  Target  : Kali Linux / Debian-based systems
 * ═══════════════════════════════════════════════════════════
 *
 *  LEGAL DISCLAIMER:
 *  This tool is intended for authorized security testing and
 *  educational purposes only. Unauthorized use against systems
 *  you do not own or have explicit permission to test is illegal.
 *  The author assumes no liability for misuse.
 *
 * ═══════════════════════════════════════════════════════════
 */

#include <iostream>
#include <string>
#include <vector>
#include <csignal>
#include "../include/scanner.hpp"
#include "../include/banner.hpp"
#include "../include/argparser.hpp"
#include "../include/logger.hpp"

// ── Global flag for graceful shutdown ──────────────────────
volatile sig_atomic_t g_running = 1;

void signal_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        std::cout << "\n[AVADON] Interrupt received. Shutting down...\n";
        g_running = 0;
    }
}

// ── Entry point ────────────────────────────────────────────
int main(int argc, char* argv[]) {

    // Register signal handlers
    std::signal(SIGINT,  signal_handler);
    std::signal(SIGTERM, signal_handler);

    // Print banner
    Banner::print();

    // Parse arguments
    ArgParser args(argc, argv);

    if (!args.parse()) {
        args.usage(argv[0]);
        return EXIT_FAILURE;
    }

    if (args.show_help()) {
        args.usage(argv[0]);
        return EXIT_SUCCESS;
    }

    // Initialize logger
    Logger logger(args.get_output_file(), args.is_verbose());
    logger.info("AVADON v1.0.0 initialized");
    logger.info("Target  : " + args.get_target());
    logger.info("Mode    : " + args.get_mode());

    // ── Build scan config ───────────────────────────────────
    ScanConfig config;
    config.target      = args.get_target();
    config.port_range  = args.get_port_range();
    config.timeout_ms  = args.get_timeout();
    config.threads     = args.get_threads();
    config.mode        = args.get_mode();
    config.stealth     = args.is_stealth();
    config.os_detect   = args.detect_os();
    config.svc_detect  = args.detect_services();

    // ── Launch scanner ──────────────────────────────────────
    Scanner scanner(config, logger);

    if (!scanner.init()) {
        logger.error("Scanner initialization failed. Are you running as root?");
        return EXIT_FAILURE;
    }

    ScanResult result = scanner.run(g_running);

    // ── Output results ──────────────────────────────────────
    scanner.print_results(result);

    if (!args.get_output_file().empty()) {
        scanner.export_results(result, args.get_output_file(),
                               args.get_output_format());
        logger.info("Results saved to: " + args.get_output_file());
    }

    logger.info("Scan complete. Total hosts: "    +
                std::to_string(result.total_hosts) +
                "  Open ports: "                   +
                std::to_string(result.open_ports));

    return EXIT_SUCCESS;
}
