cmake_minimum_required(VERSION 3.10)

project(websockets_c_server LANGUAGES C)

include(wsServer.cmake)

find_package(Threads REQUIRED)

add_executable(
    ${PROJECT_NAME}
        main.c
)

target_include_directories(
    ${PROJECT_NAME}
    PRIVATE
        ${WS_LOCATION}/include
)

target_link_libraries(
    ${PROJECT_NAME}
    PRIVATE
        Threads::Threads
        ${WS_LOCATION}/libws.a
)

set_target_properties(
    ${PROJECT_NAME}
    PROPERTIES
        C_STANDARD 11
        C_STANDARD_REQUIRED YES
        C_EXTENSIONS NO
        LINKER_LANGUAGE C
)

target_compile_options(
    ${PROJECT_NAME}
    PRIVATE
         $<$<CXX_COMPILER_ID:MSVC>:/W4 /WX>
         $<$<NOT:$<CXX_COMPILER_ID:MSVC>>:-Wall -Wextra -Wpedantic -Werror>
)

add_dependencies(${PROJECT_NAME} ws)