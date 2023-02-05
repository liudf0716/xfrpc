
cmake_minimum_required(VERSION 2.6)

message(STATUS "PROJECT PATH IS: :${PROJECT_SOURCE_DIR}")
message(STATUS "architecture is::${THIRDPARTY_STATIC_BUILD}")

if (THIRDPARTY_STATIC_BUILD STREQUAL "mips")
    set(ARCH_FLAG "linux-mips32")
    set(CROSS_C_COMPILER ${CMAKE_C_COMPILER})
elseif (THIRDPARTY_STATIC_BUILD STREQUAL "arm")
    set(ARCH_FLAG "linux-armv4")
    set(CROSS_C_COMPILER ${CMAKE_C_COMPILER})
endif()



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

if (THIRDPARTY_STATIC_BUILD STREQUAL "ON")
    execute_process(
        COMMAND ./config --static
        WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/thirdparty/openssl-1.1.1m"
    )
elseif (THIRDPARTY_STATIC_BUILD STREQUAL "mips" OR THIRDPARTY_STATIC_BUILD STREQUAL "arm")
    execute_process(
        COMMAND ./Configure ${ARCH_FLAG}  --static
        WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/thirdparty/openssl-1.1.1m"
    )
endif(THIRDPARTY_STATIC_BUILD)

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
if (THIRDPARTY_STATIC_BUILD STREQUAL "ON")
    execute_process(
        COMMAND cmake -DOPENSSL_ROOT_DIR=${PROJECT_SOURCE_DIR}/thirdparty/openssl-1.1.1m -DOPENSSL_LIBRARES=${PROJECT_SOURCE_DIR}/thirdparty/openssl-1.1.1m ..
        WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/thirdparty/libevent-2.1.10/build"
    )
else()
    execute_process(
        COMMAND cmake -DCMAKE_C_COMPILER=${CROSS_C_COMPILER} -DOPENSSL_ROOT_DIR=${PROJECT_SOURCE_DIR}/thirdparty/openssl-1.1.1m -DOPENSSL_LIBRARES=${PROJECT_SOURCE_DIR}/thirdparty/openssl-1.1.1m ..
        WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/thirdparty/libevent-2.1.10/build"
    )
endif(THIRDPARTY_STATIC_BUILD)

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
if (THIRDPARTY_STATIC_BUILD STREQUAL "ON")
    execute_process(
        COMMAND cmake ..
        WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/thirdparty/json-c/build"
    )
else()
    execute_process(
        COMMAND cmake -DCMAKE_C_COMPILER=${CROSS_C_COMPILER} ..
        WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/thirdparty/json-c/build"
    )
endif(THIRDPARTY_STATIC_BUILD)

execute_process(
    COMMAND make -j${NPROC}
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/thirdparty/json-c/build"
)


execute_process(
    COMMAND cp -f libjson-c.a ../../libs
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/thirdparty/json-c/build"
)

execute_process(
    COMMAND cp -f json.h ../../include/json-c
    WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/thirdparty/json-c/build"
)

# compile mips or arm
if (THIRDPARTY_STATIC_BUILD STREQUAL "arm" OR THIRDPARTY_STATIC_BUILD STREQUAL "mips")
    execute_process(
        COMMAND chmod +x configure
        WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/thirdparty/zlib-1.2.13"
    )
    execute_process(
        COMMAND ./configure
        WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/thirdparty/zlib-1.2.13"
    )
    execute_process(
        COMMAND make -j${NPROC}
        WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/thirdparty/zlib-1.2.13"
    )
    execute_process(
        COMMAND cp -f libz.a ../libs
        WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}/thirdparty/zlib-1.2.13"
    )
endif(THIRDPARTY_STATIC_BUILD)

