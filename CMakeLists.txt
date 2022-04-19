cmake_minimum_required(VERSION 2.6)

project(xfrp C)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/cmake/Modules/")

find_package(LibEvent)
if(NOT LibEvent_FOUND)
  message(FATAL_ERROR "libevent2 not found!")
endif(NOT LibEvent_FOUND)

find_package(OpenSSL)
if(NOT OPENSSL_FOUND)
  message(FATAL_ERROR "OpenSSL not found!")
endif(NOT OPENSSL_FOUND)

find_package(JSON-C REQUIRED)
include_directories(${JSON-C_INCLUDE_DIR})

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
	session.c
	common.c
	login.c
	proxy_tcp.c
	proxy_ftp.c
	proxy.c
	)
	
set(libs
	ssl
	crypto
	mbedcrypto
	event
	z
	m
	json-c)
	
set(test_libs
	event
	)

ADD_DEFINITIONS(-Wall -g  --std=gnu99)

add_executable(xfrpc ${src_xfrpc})
target_link_libraries(xfrpc ${libs})

install(TARGETS xfrpc
        RUNTIME DESTINATION bin
)
