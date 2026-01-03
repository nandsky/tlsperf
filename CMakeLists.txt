cmake_minimum_required(VERSION 3.10)
project(tlsperf C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

find_package(OpenSSL REQUIRED)

add_executable(tlsperf
    tlsperf.c
    tp_worker.c
    tp_util.c
    tp_tls.c
)

target_include_directories(tlsperf PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_options(tlsperf PRIVATE -Wall -Wextra -O2 -g)

# Link against OpenSSL and pthread
target_link_libraries(tlsperf PRIVATE OpenSSL::SSL OpenSSL::Crypto pthread)
