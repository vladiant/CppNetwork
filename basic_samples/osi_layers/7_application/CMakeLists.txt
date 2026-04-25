cmake_minimum_required(VERSION 3.16)
project(app_layer_sniffer
        VERSION 1.0.0
        DESCRIPTION "OSI Application Layer protocol sniffer (HTTP, HTTP/2, QUIC, DNS, TLS, SMTP, MQTT, RTP)"
        LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "Build type" FORCE)
endif()

add_compile_options(-Wall -Wextra -Wpedantic -Wshadow -Wconversion -Wnon-virtual-dtor)

# Try pkg-config first, fall back to find_library.
find_package(PkgConfig QUIET)
if(PkgConfig_FOUND)
    pkg_check_modules(PCAP QUIET libpcap)
endif()

if(NOT PCAP_FOUND)
    find_path(PCAP_INCLUDE_DIR pcap/pcap.h)
    find_library(PCAP_LIBRARY NAMES pcap)
    if(NOT PCAP_INCLUDE_DIR OR NOT PCAP_LIBRARY)
        message(FATAL_ERROR
            "libpcap not found. Install it with:\n"
            "  Debian/Ubuntu: sudo apt-get install libpcap-dev\n"
            "  Fedora/RHEL:   sudo dnf install libpcap-devel\n"
            "  Arch:          sudo pacman -S libpcap")
    endif()
    set(PCAP_INCLUDE_DIRS ${PCAP_INCLUDE_DIR})
    set(PCAP_LIBRARIES ${PCAP_LIBRARY})
endif()

add_executable(app_layer_sniffer
    src/main.cpp
    src/sniffer.cpp
    src/parsers/http.cpp
    src/parsers/http2.cpp
    src/parsers/quic.cpp
    src/parsers/dns.cpp
    src/parsers/tls.cpp
    src/parsers/smtp.cpp
    src/parsers/mqtt.cpp
    src/parsers/rtp.cpp
)

target_include_directories(app_layer_sniffer
    PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src
        ${PCAP_INCLUDE_DIRS}
)

target_link_libraries(app_layer_sniffer PRIVATE ${PCAP_LIBRARIES})

install(TARGETS app_layer_sniffer RUNTIME DESTINATION bin)
