cmake_minimum_required(VERSION 3.16)
project(presentation_layer_demo CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(-Wall -Wextra -Wpedantic)

find_package(OpenSSL REQUIRED)
find_package(ZLIB REQUIRED)

add_executable(presentation_layer_demo
    src/main.cpp
    src/encoding.cpp
    src/compression.cpp
    src/tls_info.cpp
    src/ssl_info.cpp
    src/listener.cpp
)

target_include_directories(presentation_layer_demo PRIVATE src)
target_link_libraries(presentation_layer_demo
    PRIVATE
        OpenSSL::SSL
        OpenSSL::Crypto
        ZLIB::ZLIB
)
