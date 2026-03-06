#pragma once

/*
 * logger.hpp — Logging utility
 * AVADON Network Reconnaissance Framework
 */

#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <string>

class Logger {
public:
    Logger(const std::string& filepath = "", bool verbose = false)
        : m_verbose(verbose) {
        if (!filepath.empty()) {
            m_log_path = filepath + ".log";
            m_ofs.open(m_log_path, std::ios::app);
        }
    }

    void info(const std::string& msg)  { log("INFO ",  "\033[36m", msg); }
    void warn(const std::string& msg)  { log("WARN ",  "\033[33m", msg); }
    void error(const std::string& msg) { log("ERROR",  "\033[31m", msg); }
    void debug(const std::string& msg) { if (m_verbose) log("DEBUG", "\033[35m", msg); }

private:
    bool        m_verbose = false;
    std::string m_log_path;
    std::ofstream m_ofs;

    static std::string timestamp() {
        auto now  = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        std::ostringstream ss;
        ss << std::put_time(std::localtime(&time), "%H:%M:%S");
        return ss.str();
    }

    void log(const std::string& level,
             const std::string& color,
             const std::string& msg) {
        std::string line = "[" + timestamp() + "] [" + level + "] " + msg;
        std::cout << color << line << "\033[0m\n";
        if (m_ofs.is_open()) m_ofs << line << "\n";
    }
};
