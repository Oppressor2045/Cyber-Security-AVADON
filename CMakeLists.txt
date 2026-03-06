cmake_minimum_required(VERSION 3.16)
project(AVADON VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Release flags
set(CMAKE_CXX_FLAGS_RELEASE "-O2 -DNDEBUG")
set(CMAKE_CXX_FLAGS_DEBUG   "-g -fsanitize=address,undefined")

# Sources
add_executable(avadon
    src/main.cpp
    src/scanner.cpp
)

target_include_directories(avadon PRIVATE include)

# Threads
find_package(Threads REQUIRED)
target_link_libraries(avadon PRIVATE Threads::Threads)

# Install
install(TARGETS avadon DESTINATION bin)

message(STATUS "AVADON v${PROJECT_VERSION} — build configured")
