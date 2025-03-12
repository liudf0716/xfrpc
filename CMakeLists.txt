
# Minimum CMake version 
cmake_minimum_required(VERSION 3.5...3.27)
project(xfrp C)

# Build options
option(DEBUG "Enable debug mode" OFF)
option(THIRDPARTY_STATIC_BUILD "Build with static third party libraries" OFF)
option(ENABLE_SANITIZER "Enable sanitizer(Debug+Gcc/Clang/AppleClang)" ON)

# Configure static/dynamic build
if(THIRDPARTY_STATIC_BUILD)
    add_subdirectory(${PROJECT_SOURCE_DIR}/thirdparty/)
    include_directories(
        ${PROJECT_SOURCE_DIR}/thirdparty/include/libevent
        ${PROJECT_SOURCE_DIR}/thirdparty/include/
    )
    link_directories(${PROJECT_SOURCE_DIR}/thirdparty/libs/)
    set(EXTRA_LIBS dl pthread)
else()
    set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")
    
    # Find required packages
    find_package(LibEvent REQUIRED)
    find_package(OpenSSL REQUIRED)
    find_package(JSON-C REQUIRED)
    find_package(ZLIB REQUIRED)
    
    include_directories(
        ${JSON-C_INCLUDE_DIR}
        ${ZLIB_INCLUDE_DIRS}
    )
endif()

# Sanitizer configuration
macro(check_asan _RESULT)
    include(CheckCSourceRuns)
    set(CMAKE_REQUIRED_FLAGS "-fsanitize=address")
    check_c_source_runs("int main() { return 0; }" ${_RESULT})
    unset(CMAKE_REQUIRED_FLAGS)
endmacro()

if(ENABLE_SANITIZER AND NOT MSVC)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        check_asan(HAS_ASAN)
        if(HAS_ASAN)
            message(STATUS "Adding address sanitizer")
            set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fsanitize=address -fsanitize=leak")
            list(APPEND EXTRA_LIBS asan)
        else()
            message(STATUS "Sanitizer not supported with current toolchain")
        endif()
    else()
        message(STATUS "Sanitizer only available in Debug build")
    endif()
endif()

# Source files
set(CORE_SOURCES
    main.c
    client.c
    config.c
    control.c
    ini.c
    msg.c
    xfrpc.c
    debug.c
    zip.c
    commandline.c
    crypto.c
    fastpbkdf2.c
    utils.c
    common.c
    login.c
)

set(PROXY_SOURCES
    proxy_tcp.c
    proxy_udp.c
    proxy_ftp.c
    proxy.c
    tcpmux.c
    tcp_redir.c
    mongoose.c
)

set(PLUGIN_SOURCES
    plugins/telnetd.c
    plugins/instaloader.c
    plugins/httpd.c
    plugins/youtubedl.c
)

# Combine all sources
set(src_xfrpc
    ${CORE_SOURCES}
    ${PROXY_SOURCES}
    ${PLUGIN_SOURCES}
)

# Required libraries
set(SYSTEM_LIBS
    pthread
    m
    crypt
    dl
)

set(EXTERNAL_LIBS
    ssl
    crypto
    event
    ${JSON-C_LIBRARIES}
    ${ZLIB_LIBRARIES}
)

# Set debug flags
if(DEBUG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0")
    add_definitions(-DDEBUG)
    message(STATUS "Debug mode: ON (-g -O0 flags added, DEBUG defined)")
else()
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O2")
    message(STATUS "Debug mode: OFF (optimized build)")
endif()

# Compiler flags
add_definitions(
    -D_GNU_SOURCE
    -Wall
    -Werror
)

# Build target
add_executable(xfrpc ${src_xfrpc})

# Link libraries
target_link_libraries(xfrpc PRIVATE
    ${EXTERNAL_LIBS}
    ${SYSTEM_LIBS}
    ${EXTRA_LIBS}
)

# Installation
install(TARGETS xfrpc DESTINATION bin)