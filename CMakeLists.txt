cmake_minimum_required(VERSION 2.8.12)

project(xfrp C)


if (THIRDPARTY_STATIC_BUILD STREQUAL "ON" OR  THIRDPARTY_STATIC_BUILD STREQUAL "mips" OR THIRDPARTY_STATIC_BUILD STREQUAL "arm")
	add_subdirectory(${PROJECT_SOURCE_DIR}/thirdparty/)
	include_directories(${PROJECT_SOURCE_DIR}/thirdparty/include/libevent)
	include_directories(${PROJECT_SOURCE_DIR}/thirdparty/include/)
	link_directories(${PROJECT_SOURCE_DIR}/thirdparty/libs/)
	set(static_libs dl pthread)
else()
	set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

	find_package(LibEvent)
	if(NOT LibEvent_FOUND)
	  message(FATAL_ERROR "LibEvent not found!")
	endif(NOT LibEvent_FOUND)

	find_package(OpenSSL)
	if(NOT OPENSSL_FOUND)
	  message(FATAL_ERROR "OpenSSL not found!")
	endif(NOT OPENSSL_FOUND)

	find_package(JSON-C REQUIRED)
	include_directories(${JSON-C_INCLUDE_DIR})
endif(THIRDPARTY_STATIC_BUILD)

macro(check_asan _RESULT)
    include(CheckCSourceRuns)
    set(CMAKE_REQUIRED_FLAGS "-fsanitize=address")
    check_c_source_runs(
            [====[
int main()
{
  return 0;
}
]====]
            ${_RESULT}
    )
    unset(CMAKE_REQUIRED_FLAGS)
endmacro()

# Enable address sanitizer
option(ENABLE_SANITIZER "Enable sanitizer(Debug+Gcc/Clang/AppleClang)" ON)
if(ENABLE_SANITIZER AND NOT MSVC)
    if(CMAKE_BUILD_TYPE STREQUAL "Debug")
        check_asan(HAS_ASAN)
        if(HAS_ASAN)
		message(WARNING "add sanitizer")
		set(asan_c_flags "-fsanitize=address -fsanitize=leak")
		set(asan_c_libs "asan")
        else()
            message(WARNING "sanitizer is no supported with current tool-chains")
        endif()
    else()
        message(WARNING "Sanitizer supported only for debug type")
    endif()
endif()

set(src_xfrpc
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
	proxy_tcp.c
	proxy_udp.c
	proxy_ftp.c
	proxy.c
	tcpmux.c
	tcp_redir.c
	mongoose.c
	)

set(src_xfrpc_plugins
	plugins/telnetd.c
	plugins/instaloader.c
	plugins/httpd.c
	plugins/youtubedl.c)

set(libs
	ssl
	crypto
	event
	z
	m
	json-c
	crypt
	pthread)
	
set(test_libs
	event
	)

ADD_DEFINITIONS(-Wall -g -Wno-deprecated-declarations --std=gnu99 ${asan_c_flags})

if (STATIC_BUILD STREQUAL "ON")
  add_link_options(-static)
endif (STATIC_BUILD)

add_executable(xfrpc ${src_xfrpc} ${src_xfrpc_plugins})
target_link_libraries(xfrpc ${libs} ${static_libs} ${asan_c_libs})

install(TARGETS xfrpc
        RUNTIME DESTINATION bin
)
