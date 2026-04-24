cmake_minimum_required(VERSION 3.16)
project(transport_layer_sniffer CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(-Wall -Wextra -Wpedantic -Wshadow -Wold-style-cast -Wnon-virtual-dtor)

add_executable(transport_sniffer
    src/main.cpp
    src/transport_sniffer.cpp
)

target_include_directories(transport_sniffer PRIVATE src)
