#pragma once

/*
 * banner.hpp — ASCII art banner
 * AVADON Network Reconnaissance Framework
 */

#include <iostream>

class Banner {
public:
    static void print() {
        std::cout << R"(
  ______   ____   __ ____   ____  ____  _   _
 /  _  \  \    \ /  /    | |    \|    \| \ | |
|  |_|  |  \    V  /|    | |  |  |  |  |  \| |
|   _   |   \     / |    | |  |  |  |  |     |
|__| |__|    \___/  |____| |____/|____/|_|\__|

  Network Reconnaissance Framework  v1.0.0
  Author  : Oppressor2045
  OS      : Kali Linux
  WARNING : Authorized use only.
)";
        std::cout << "  ─────────────────────────────────────────────\n\n";
    }
};
