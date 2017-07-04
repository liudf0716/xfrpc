cmake_minimum_required(VERSION 2.6)

project(xfrp C)

set(src_xfrp_client
	main.c
  	client.c
  	config.c
  	control.c
	frame.c
  	ini.c
  	msg.c
	xfrp_client.c
	debug.c
	zip.c
	commandline.c
	crypto.c
	fastpbkdf2.c
	utils.c
	session.c
	common.c
	login.c
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

add_executable(xfrp_client ${src_xfrp_client})
target_link_libraries(xfrp_client ${libs})

install(TARGETS xfrp_client
        RUNTIME DESTINATION bin
)
