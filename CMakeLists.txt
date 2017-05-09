cmake_minimum_required(VERSION 2.6)

project(xfrp C)

set(src_xfrp_client
	main.c
  	client.c
  	config.c
  	control.c
  	ini.c
  	msg.c
	xfrp_client.c
	debug.c
	commandline.c
	)
	
set(libs
	openssl
	event
	json-c)

ADD_DEFINITIONS(-Wall -g  --std=gnu99 -Wmissing-declarations)

add_executable(xfrp_client ${src_xfrp_client})
target_link_libraries(xfrp_client ${libs})

install(TARGETS xfrp_client 
        RUNTIME DESTINATION bin
)
