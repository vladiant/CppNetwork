cmake_minimum_required(VERSION 3.10)

project(CppNetwork)

# TCP server
find_package(Threads REQUIRED)

add_executable(
    TcpServer
    tcp/server.cpp
)

set_target_properties(
    TcpServer
    PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED YES
        CXX_EXTENSIONS NO
)

target_compile_options(
    TcpServer
    PRIVATE
         $<$<CXX_COMPILER_ID:MSVC>:/W4 /WX>
         $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
)

target_include_directories(
    TcpServer 
    PUBLIC 
      third_party/asio
)

target_link_libraries(
    TcpServer
    PRIVATE
        Threads::Threads
)

