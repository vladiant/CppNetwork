cmake_minimum_required(VERSION 3.16)
project(osi_physical_layer LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
    message(FATAL_ERROR "This project targets Linux only (uses AF_PACKET / ethtool ioctls).")
endif()

add_compile_options(-Wall -Wextra -Wpedantic)

add_executable(osi_physical src/main.cpp)
