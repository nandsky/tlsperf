cmake_minimum_required(VERSION 3.10)
project(tlsperf C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)

add_executable(tlsperf tlsperf.c)

target_compile_options(tlsperf PRIVATE -Wall -Wextra -O2)

# Link against OpenSSL
target_link_libraries(tlsperf PRIVATE OpenSSL::SSL OpenSSL::Crypto)
