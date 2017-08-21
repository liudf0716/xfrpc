cmake_minimum_required(VERSION 2.6)

project(xfrp C)

set(src_xfrpc
	main.c
  	client.c
  	config.c
  	control.c
	frame.c
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
