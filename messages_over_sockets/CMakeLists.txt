cmake_minimum_required(VERSION 3.10)

project(CppNetwork)

# Library
add_library(
    MessagesLib
    common.h
)

set_target_properties(
    MessagesLib
    PROPERTIES
        CXX_STANDARD 20
        CXX_STANDARD_REQUIRED YES
        CXX_EXTENSIONS NO
        LINKER_LANGUAGE CXX
)

target_compile_options(
    MessagesLib
    PRIVATE
         $<$<CXX_COMPILER_ID:MSVC>:/W4 /WX>
         $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
)

target_include_directories(
    MessagesLib
    PUBLIC
       .
)

# Server
find_package(Threads REQUIRED)

add_executable(
    MessagesServer
    server.h
    server.cpp
)

set_target_properties(
    MessagesServer
    PROPERTIES
        CXX_STANDARD 20
        CXX_STANDARD_REQUIRED YES
        CXX_EXTENSIONS NO
)

target_compile_options(
    MessagesServer
    PRIVATE
         $<$<CXX_COMPILER_ID:MSVC>:/W4 /WX>
         $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
)

target_include_directories(
    MessagesServer
    PUBLIC
       MessagesLib
)

target_link_libraries(
    MessagesServer
    PRIVATE
       MessagesLib
)

# Sample client
add_executable(
    MessagesClient
    client.h
    client.cpp
)

set_target_properties(
    MessagesClient
    PROPERTIES
        CXX_STANDARD 20
        CXX_STANDARD_REQUIRED YES
        CXX_EXTENSIONS NO
)

target_compile_options(
    MessagesClient
    PRIVATE
         $<$<CXX_COMPILER_ID:MSVC>:/W4 /WX>
         $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
)

target_include_directories(
    MessagesClient
    PUBLIC
       MessagesLib
)

target_link_libraries(
    MessagesClient
    PRIVATE
       MessagesLib
)

