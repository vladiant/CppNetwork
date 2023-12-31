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

# TCP sample client
add_executable(
    TcpClient
    tcp/client.cpp
)

set_target_properties(
    TcpClient
    PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED YES
        CXX_EXTENSIONS NO
)

target_compile_options(
    TcpClient
    PRIVATE
         $<$<CXX_COMPILER_ID:MSVC>:/W4 /WX>
         $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
)

target_include_directories(
    TcpClient
    PUBLIC
      third_party/asio
)

target_link_libraries(
    TcpClient
    PRIVATE
        Threads::Threads
)

# UDP server
find_package(Threads REQUIRED)

add_executable(
    UdpServer
    udp/server.cpp
)

set_target_properties(
    UdpServer
    PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED YES
        CXX_EXTENSIONS NO
)

target_compile_options(
    UdpServer
    PRIVATE
         $<$<CXX_COMPILER_ID:MSVC>:/W4 /WX>
         $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
)

target_include_directories(
    UdpServer
    PUBLIC 
      third_party/asio
)

target_link_libraries(
    UdpServer
    PRIVATE
        Threads::Threads
)

# UDP sample client
add_executable(
    UdpClient
    udp/client.cpp
)

set_target_properties(
    UdpClient
    PROPERTIES
        CXX_STANDARD 17
        CXX_STANDARD_REQUIRED YES
        CXX_EXTENSIONS NO
)

target_compile_options(
    UdpClient
    PRIVATE
         $<$<CXX_COMPILER_ID:MSVC>:/W4 /WX>
         $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic>
)

target_include_directories(
    UdpClient
    PUBLIC
      third_party/asio
)

target_link_libraries(
    UdpClient
    PRIVATE
        Threads::Threads
)
