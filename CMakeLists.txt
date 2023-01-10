cmake_minimum_required(VERSION 2.6)

project(xfrp C)


if (THIRDPARTY_STATIC_BUILD STREQUAL "ON") # add x86 iot device support
	execute_process(COMMAND uname -r OUTPUT_VARIABLE UNAME_RESULT OUTPUT_STRIP_TRAILING_WHITESPACE)
	message(-- " Kernel version: " ${UNAME_RESULT})
	string(REGEX MATCH "[0-9]+.[0-9]+" LINUX_KERNEL_VERSION ${UNAME_RESULT})

	if (LINUX_KERNEL_VERSION LESS 3.11)
		message(STATUS "Linux kernel version less than 3.10")
		link_directories(${PROJECT_SOURCE_DIR}/thirdparty/libs/x86/kernel_3_10)
	else()
		message(STATUS "Linux kernel version greater than 3.10")
		link_directories(${PROJECT_SOURCE_DIR}/thirdparty/libs/x86/kernel_5_4)
	endif()
	include_directories(${PROJECT_SOURCE_DIR}/thirdparty/include/libevent)
	include_directories(${PROJECT_SOURCE_DIR}/thirdparty/include/)
	set(x86-libs dl pthread)
	link_directories(${PROJECT_SOURCE_DIR}/thirdparty/libs/x86)

else()

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

endif(THIRDPARTY_STATIC_BUILD)

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
	proxy_ftp.c
	proxy.c
	tcpmux.c
	)
	
set(libs
	ssl
	crypto
	event
	z
	m
	json-c)
	
set(test_libs
	event
	)

ADD_DEFINITIONS(-Wall -g  --std=gnu99)

if (STATIC_BUILD STREQUAL "ON")
  add_link_options(-static)
endif (STATIC_BUILD)

add_executable(xfrpc ${src_xfrpc})
target_link_libraries(xfrpc ${libs} ${x86-libs})

install(TARGETS xfrpc
        RUNTIME DESTINATION bin
)
