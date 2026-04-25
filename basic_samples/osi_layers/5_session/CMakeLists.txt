cmake_minimum_required(VERSION 3.16)
project(osi_session_layer CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

add_compile_options(-Wall -Wextra -Wpedantic)

add_executable(session_layer
    src/main.cpp
    src/session_layer.cpp
    src/listener.cpp
)

target_include_directories(session_layer PRIVATE include)
