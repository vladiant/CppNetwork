cmake_minimum_required(VERSION 3.10)

include(ExternalProject)

set(WS_LOCATION ${CMAKE_BINARY_DIR}/external)

ExternalProject_Add(ws
    GIT_REPOSITORY https://github.com/Theldus/wsServer.git
    GIT_TAG eb45cd5d2fcf748a06f50a7e0a5d781c198185b8
    BUILD_COMMAND make ws
    INSTALL_COMMAND ""
    SOURCE_DIR ${WS_LOCATION}
    BINARY_DIR ${WS_LOCATION}
)