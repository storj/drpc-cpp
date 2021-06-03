# Copyright (c) 2021 Storj Labs, Inc.
# See LICENSE for copying information.

set(CMAKE_CXX_STANDARD 20)

find_package(OpenSSL REQUIRED)
find_package(Protobuf REQUIRED)

find_package(Threads)

set(HEADER_LIST
    "${drpc_cpp_SOURCE_DIR}/include/drpc.h"
    "${drpc_cpp_SOURCE_DIR}/include/drpc/wire.h"
    "${drpc_cpp_SOURCE_DIR}/include/drpc/concepts.h"
    "${drpc_cpp_SOURCE_DIR}/include/drpc/stream.h"
    "${drpc_cpp_SOURCE_DIR}/include/drpc/conn.h"
    "${drpc_cpp_SOURCE_DIR}/include/drpc/ssl.h"
)

add_library(drpc SHARED wire.cpp)

target_link_libraries(drpc PUBLIC ${CMAKE_THREAD_LIBS_INIT} ${Protobuf_LIBRARIES} ${OPENSSL_LIBRARIES})

# set $ASIO_INCLUDE_DIR with -D if needed
target_include_directories(drpc PUBLIC ${drpc_cpp_SOURCE_DIR}/include ${ASIO_INCLUDE_DIRS} ${Protobuf_INCLUDE_DIRS} ${OPENSSL_INCLUDE_DIR})

set(CMAKE_REQUIRED_INCLUDES ${ASIO_INCLUDE_DIRS})

check_include_file_cxx("asio.hpp" ASIO_found)
if(NOT ASIO_found)
    message(FATAL_ERROR "ASIO not found; try setting -DASIO_INCLUDE_DIRS=...")
endif()
