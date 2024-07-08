cmake_minimum_required(VERSION 3.10)

set(CMAKE_CXX_STANDARD 17)

if(MSVC)
    add_compile_options("$<$<C_COMPILER_ID:MSVC>:/source-charset:utf-8>")
    add_compile_options("$<$<CXX_COMPILER_ID:MSVC>:/source-charset:utf-8>")
endif()

project(BitLogin VERSION 0.11.0)

configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/project.h.in"
    "${CMAKE_BINARY_DIR}/project.h"
)
configure_file(
    "${CMAKE_CURRENT_SOURCE_DIR}/cmake/execname.in"
    "${CMAKE_BINARY_DIR}/execname"
)

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)
include_directories(${CMAKE_BINARY_DIR})

# Add source files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/src SRC_LIST)
add_executable(${PROJECT_NAME} "${SRC_LIST}")

# Echo output name
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                   COMMAND ${CMAKE_COMMAND} -E echo
                   "Executable path: $<TARGET_FILE:${PROJECT_NAME}>")
