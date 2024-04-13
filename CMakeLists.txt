cmake_minimum_required(VERSION 3.10)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_BUILD_TYPE Release)

project(BitLogin)

# ===================================
# Begin compiling setting
# ===================================

# Configure vcpkg to use static link
if(VCPKG_TARGET_TRIPLET MATCHES "-static")
    string(REPLACE "/MD" "/MT" CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS})
    string(REPLACE "/MD" "/MT" CMAKE_CXX_FLAGS_DEBUG ${CMAKE_CXX_FLAGS_DEBUG})
    string(REPLACE "/MD" "/MT" CMAKE_CXX_FLAGS_RELEASE ${CMAKE_CXX_FLAGS_RELEASE})
endif()

# Configure openssl to use static link
set(OPENSSL_USE_STATIC_LIBS TRUE)

# ===================================
# End compiling setting
# ===================================

# ===================================
# Begin finding dependencies
# ===================================

# For OpenSSL and fmt, the easiest way to install them is vcpkg , apt or brew.
find_package(OpenSSL REQUIRED)
find_package(fmt CONFIG REQUIRED)

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

# Echo output name
add_custom_command(TARGET ${PROJECT_NAME} POST_BUILD
                   COMMAND ${CMAKE_COMMAND} -E echo
                   "Executable path: $<TARGET_FILE:${PROJECT_NAME}>")
