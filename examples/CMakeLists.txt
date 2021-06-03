# Copyright (c) 2021 Storj Labs, Inc.
# See LICENSE for copying information.

set(CMAKE_CXX_STANDARD 20)

find_package(Protobuf REQUIRED)

set(ProtoFiles pb/sesamestreet.proto)
protobuf_generate_cpp(ProtoSources ProtoHeaders ${ProtoFiles})

add_executable(client client.cpp pb/sesamestreet_drpc.pb.h ${ProtoSources} ${ProtoHeaders})

target_link_libraries(client drpc)
