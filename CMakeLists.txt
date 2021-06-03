# Copyright (c) 2021 Storj Labs, Inc.
# See LICENSE for copying information.

cmake_minimum_required(VERSION 3.16)
project(
    drpc_cpp
    DESCRIPTION "DRPC implementation in C++20"
    LANGUAGES CXX)

#set(CMAKE_DEBUG_TARGET_PROPERTIES INCLUDE_DIRECTORIES)
#set(CMAKE_VERBOSE_MAKEFILE on)

if(CMAKE_CXX_COMPILER_ID MATCHES GNU)
    add_compile_options(-fcoroutines -pthread)
endif()
add_compile_options(-Wall -Wextra -pedantic -Werror)

add_subdirectory(src)

# Only do the following if this is the main project, and not included in something else
if (CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME)
    set(CMAKE_CXX_STANDARD 20)

    set_property(GLOBAL PROPERTY USE_FOLDERS ON)

    add_subdirectory(examples)

    # Testing only available if this is the main app
    enable_testing()
endif()

# Testing only available if this is the main app
# Emergency override MODERN_CMAKE_BUILD_TESTING provided as well
if((CMAKE_PROJECT_NAME STREQUAL PROJECT_NAME OR MODERN_CMAKE_BUILD_TESTING)
        AND BUILD_TESTING)
    add_subdirectory(tests)
endif()
