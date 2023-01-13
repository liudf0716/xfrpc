
cmake_minimum_required(VERSION 2.6)

message(STATUS "PROJECT PATH IS: :${PROJECT_SOURCE_DIR}")
#openssl compile and add libs to libs file
message(STATUS "compiling openssl")
execute_process(
    COMMAND rm -rf ../libs
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/thirdparty/openssl-1.1.1m"
)
execute_process(
    COMMAND mkdir ../libs
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/thirdparty/openssl-1.1.1m"
)

execute_process(
    COMMAND chmod +x config
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/thirdparty/openssl-1.1.1m"
)

execute_process(
    COMMAND chmod +x Configure
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/thirdparty/openssl-1.1.1m"
)

execute_process(
    COMMAND ./config --static
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/thirdparty/openssl-1.1.1m"
)

execute_process(
    COMMAND make -j${NPROC}
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/thirdparty/openssl-1.1.1m"
)

execute_process(
    COMMAND cp -f libcrypto.a ../libs
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/thirdparty/openssl-1.1.1m"
)

execute_process(
    COMMAND cp -f libssl.a ../libs
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/thirdparty/openssl-1.1.1m"
)

execute_process(
    COMMAND cp -rf include/openssl ../include
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/thirdparty/openssl-1.1.1m"
)

#libevent compile and add libs to libs file
message(STATUS "compiling libevnet")
execute_process(
    COMMAND rm -rf build
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/thirdparty/libevent-2.1.10"
)

execute_process(
    COMMAND mkdir build
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/thirdparty/libevent-2.1.10"
)

execute_process(
    COMMAND cmake -DOPENSSL_ROOT_DIR=${PROJECT_SOURCE_DIR}/thirdparty/openssl-1.1.1m -DOPENSSL_LIBRARES=${PROJECT_SOURCE_DIR}/thirdparty/openssl-1.1.1m ..
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/thirdparty/libevent-2.1.10/build"
)

execute_process(
    COMMAND make -j${NPROC}
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/thirdparty/libevent-2.1.10/build"
)
# wait libevent create libs
set(EVENT_BUILD_PATH ${PROJECT_SOURCE_DIR}/thirdparty/libevent-2.1.10/build)
set(LIBS_PATH ${PROJECT_SOURCE_DIR}/thirdparty/libs)

file(GLOB EVENT_LIBS_PATH
	"${EVENT_BUILD_PATH}/lib/libevent*.a"	
)
file(COPY ${EVENT_LIBS_PATH} DESTINATION ${LIBS_PATH})

#json-c compile and add libs to libs file
message(STATUS "compiling json-c")
execute_process(
    COMMAND rm -rf build
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/thirdparty/json-c"
)

execute_process(
    COMMAND mkdir build
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/thirdparty/json-c"
)

execute_process(
    COMMAND cmake ..
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/thirdparty/json-c/build"
)

execute_process(
    COMMAND make -j${NPROC}
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/thirdparty/json-c/build"
)


execute_process(
    COMMAND cp -f libjson-c.a ../../libs
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/thirdparty/json-c/build"
)

