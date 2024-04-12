cmake_minimum_required(VERSION 3.10)

macro(get_from_github DEPENDENCY_NAME GIT_REPOSITORY)
    include(FetchContent)

    message(STATUS "Getting ${DEPENDENCY_NAME} via ${GIT_REPOSITORY}...")

    FetchContent_Declare(
        ${DEPENDENCY_NAME}
        GIT_REPOSITORY ${GIT_REPOSITORY}
    )
    FetchContent_MakeAvailable(${DEPENDENCY_NAME})

    message(STATUS "Getting ${DEPENDENCY_NAME} done.")

endmacro()

set(CMAKE_CXX_STANDARD 20)

project(BitLogin)

# If use vcpkg, set static link
if (VCPKG_TARGET_TRIPLET MATCHES "-static")
    string(REPLACE "/MD" "/MT" CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS})
    string(REPLACE "/MD" "/MT" CMAKE_CXX_FLAGS_DEBUG ${CMAKE_CXX_FLAGS_DEBUG})
    string(REPLACE "/MD" "/MT" CMAKE_CXX_FLAGS_RELEASE ${CMAKE_CXX_FLAGS_RELEASE})
endif ()

# ===================================
# Begin finding dependencies
# ===================================

# For OpenSSL and fmt, the easiest way to install them is vcpkg , apt or brew.
find_package(OpenSSL REQUIRED)
find_package(fmt CONFIG REQUIRED)

# For argparse and httplib, we need to get them from github (on linux and apple) or use vcpkg (on windows)
# Change the url if needed
if (CMAKE_HOST_SYSTEM_NAME MATCHES "Linux" OR CMAKE_HOST_SYSTEM_NAME MATCHES "Darwin")
    get_from_github(argparse https://github.com/p-ranav/argparse.git)
    get_from_github(httplib https://github.com/yhirose/cpp-httplib.git)
elseif (CMAKE_HOST_SYSTEM_NAME MATCHES "Windows")
    find_package(httplib CONFIG REQUIRED)
    find_package(argparse CONFIG REQUIRED)
else()
    message(FATAL_ERROR "Unsupported platform")
endif ()

# ===================================
# End finding dependencies
# ===================================

# Include directories
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

# Add source files
aux_source_directory(${CMAKE_CURRENT_SOURCE_DIR}/src SRC_LIST)
add_executable(${PROJECT_NAME} "${SRC_LIST}")

# Link dependency libraries
target_link_libraries(${PROJECT_NAME} PRIVATE OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(${PROJECT_NAME} PRIVATE fmt::fmt)
target_link_libraries(${PROJECT_NAME} PRIVATE httplib::httplib)
target_link_libraries(${PROJECT_NAME} PRIVATE argparse::argparse)

# Echo output name
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                   COMMAND ${CMAKE_COMMAND} -E echo
                   "Executable path: $<TARGET_FILE:${PROJECT_NAME}>")