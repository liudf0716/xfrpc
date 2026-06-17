
# Minimum CMake version 
cmake_minimum_required(VERSION 3.5...3.27)
project(xfrp C)

# Build options
option(DEBUG "Enable debug mode" OFF)
option(ENABLE_SANITIZER "Enable sanitizer(Debug+Gcc/Clang/AppleClang)" ON)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

# Find required packages from the system
find_package(LibEvent REQUIRED)
find_package(JSON-C REQUIRED)
find_package(ZLIB REQUIRED)

# TLS/SSL backend selection
# tls.c uses real OpenSSL API (bufferevent_openssl requires struct ssl_st *).
# crypto.c uses wolfSSL for PBKDF2/AES when USE_WOLFSSL is defined.
# When wolfSSL is the backend, link both wolfSSL and OpenSSL.
option(USE_WOLFSSL "Use wolfSSL as TLS backend (default: ON)" ON)
if(USE_WOLFSSL)
    find_library(WOLFSSL_LIB wolfssl)
    find_path(WOLFSSL_INCLUDE_DIR wolfssl/options.h)
    if(WOLFSSL_LIB AND WOLFSSL_INCLUDE_DIR)
        set(SSL_BACKEND "wolfssl")
        include_directories(${WOLFSSL_INCLUDE_DIR})
        add_definitions(-DUSE_WOLFSSL)
        # tls.c uses real OpenSSL for libevent bufferevent_ssl compat.
        # crypto.c uses wolfSSL for PBKDF2/AES. Link both.
        find_package(OpenSSL)
        if(OPENSSL_FOUND)
            set(SSL_LIBRARIES ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY} ${WOLFSSL_LIB})
            message(STATUS "TLS backend: OpenSSL (${OPENSSL_SSL_LIBRARY}) + wolfSSL (${WOLFSSL_LIB})")
        else()
            set(SSL_LIBRARIES ${WOLFSSL_LIB})
            message(STATUS "TLS backend: wolfSSL only (${WOLFSSL_LIB})")
        endif()
    else()
        message(STATUS "wolfSSL not found, falling back to OpenSSL")
        set(USE_WOLFSSL OFF)
    endif()
endif()
if(NOT USE_WOLFSSL)
    find_package(OpenSSL)
    if(OPENSSL_FOUND)
        set(SSL_BACKEND "openssl")
        set(SSL_LIBRARIES ${OPENSSL_SSL_LIBRARY} ${OPENSSL_CRYPTO_LIBRARY})
        message(STATUS "TLS backend: OpenSSL (${OPENSSL_SSL_LIBRARY})")
    else()
        message(FATAL_ERROR "No TLS library found. Install wolfSSL or OpenSSL.")
    endif()
endif()

# Optional: ngtcp2 for QUIC support (Xtcp P2P)
# The ngtcp2 crypto backend is auto-detected based on what's installed.
option(ENABLE_QUIC "Enable QUIC transport via ngtcp2" OFF)
if(ENABLE_QUIC)
    find_library(NGTCP2_LIB ngtcp2)
    find_path(NGTCP2_INCLUDE_DIR ngtcp2/ngtcp2.h)
    # Auto-detect crypto backend: try wolfssl first, then openssl (ossl)
    find_library(NGTCP2_CRYPTO_LIB ngtcp2_crypto_wolfssl)
    if(NGTCP2_CRYPTO_LIB)
        set(NGTCP2_CRYPTO_BACKEND "wolfssl")
    else()
        find_library(NGTCP2_CRYPTO_LIB ngtcp2_crypto_ossl)
        if(NGTCP2_CRYPTO_LIB)
            set(NGTCP2_CRYPTO_BACKEND "openssl")
        endif()
    endif()
    if(NGTCP2_LIB AND NGTCP2_CRYPTO_LIB AND NGTCP2_INCLUDE_DIR)
        message(STATUS "QUIC support: ON (ngtcp2 found, crypto backend: ${NGTCP2_CRYPTO_BACKEND})")
        add_definitions(-DHAVE_NGTCP2)
        if(NGTCP2_CRYPTO_BACKEND STREQUAL "wolfssl")
            add_definitions(-DUSE_NGTCP2_WOLFSSL)
        elseif(NGTCP2_CRYPTO_BACKEND STREQUAL "openssl")
            add_definitions(-DUSE_NGTCP2_OSSL)
        endif()
        include_directories(${NGTCP2_INCLUDE_DIR})
        set(HAS_QUIC ON)
    else()
        message(WARNING "QUIC support: OFF (ngtcp2 not found, set NGTCP2_LIB/NGTCP2_INCLUDE_DIR)")
    endif()
else()
    message(STATUS "QUIC support: OFF (set -DENABLE_QUIC=ON to enable)")
endif()

include_directories(
    ${JSON-C_INCLUDE_DIR}
    ${ZLIB_INCLUDE_DIRS}
)

set(EXTRA_LIBS)

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
    toml_parser.c
    vendor/tomlc17/tomlc17.c
    crypto_stream.c
    msg.c
    xfrpc.c
    debug.c
    zip.c
    commandline.c
    crypto.c
    utils.c
    common.c
    login.c
    tls.c
    health_check.c
)

set(PROXY_SOURCES
    proxy_tcp.c
    proxy_udp.c
    proxy_ftp.c
    proxy.c
    tcpmux.c
    visitor.c
    xtcp_visitor.c
    xtcp_client.c
    nathole.c
    tcp_redir.c
    mongoose.c
)
# quic_transport.c is added conditionally via ENABLE_QUIC above;
# quic_client_transport.c is always compiled (has #ifdef stubs)
if(HAS_QUIC)
    list(APPEND PROXY_SOURCES quic_transport.c quic_client_transport.c)
else()
    list(APPEND PROXY_SOURCES quic_client_transport.c)
endif()

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
    ${SSL_LIBRARIES}
    event
    event_openssl
    ${JSON-C_LIBRARIES}
    ${ZLIB_LIBRARIES}
)

# Add QUIC libraries if enabled
if(HAS_QUIC)
    list(APPEND EXTERNAL_LIBS ${NGTCP2_CRYPTO_LIB} ${NGTCP2_LIB})
    if(NGTCP2_CRYPTO_BACKEND STREQUAL "wolfssl")
        list(APPEND EXTERNAL_LIBS wolfssl)
    endif()
endif()

# Set debug flags
if(DEBUG)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O0")
    add_definitions(-DXFRPC_DEBUG)
    message(STATUS "Debug mode: ON (-g -O0 flags added, XFRPC_DEBUG defined)")
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

# Suppress stringop-truncation warnings from strncpy in legacy code
target_compile_options(xfrpc PRIVATE -Wno-stringop-truncation)

# Link libraries
target_link_libraries(xfrpc PRIVATE
    ${EXTERNAL_LIBS}
    ${SYSTEM_LIBS}
    ${EXTRA_LIBS}
)

# Installation
install(TARGETS xfrpc DESTINATION bin)