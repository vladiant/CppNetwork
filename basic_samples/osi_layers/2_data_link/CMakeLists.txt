cmake_minimum_required(VERSION 3.20)

project(datalink_reader LANGUAGES CXX)

# BtCommon
add_executable(
    ${PROJECT_NAME}
    main.cpp
)

set_target_properties(
    ${PROJECT_NAME}
    PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED YES
        CXX_EXTENSIONS NO
)

target_compile_options(
    ${PROJECT_NAME}
    PUBLIC
         -Wall -Wextra -Wpedantic
)

