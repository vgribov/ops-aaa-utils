# (C) Copyright 2016 Hewlett Packard Enterprise Development LP
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

cmake_minimum_required (VERSION 2.8)

project ("stub_getpwnam")

set (INCL_DIR ${CMAKE_SOURCE_DIR}/include)
set (LIBSTUB_GETPWNAM stub_getpwnam)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DREMOTE_USER=\"remote_user\" -std=gnu99 -Wall -Werror")


add_definitions(-DHAVE_CONFIG_H -DHAVE_SOCKLEN_T)

# Rules to locate needed libraries
include(FindPkgConfig)
pkg_check_modules(OVSCOMMON REQUIRED libovscommon)
pkg_check_modules(OVSDB REQUIRED libovsdb)
pkg_check_modules(OPSCLI REQUIRED ops-cli)

include_directories (${INCL_DIR}
                     ${PROJECT_SOURCE_DIR}
                     ${OVSCOMMON_INCLUDE_DIRS}
                     ${OPSCLI_INCLUDE_DIRS}
                    )

# CLI libraries source files
set (SOURCES_LIB ${PROJECT_SOURCE_DIR}/getpwnam-preload.c
    )


add_library (${LIBSTUB_GETPWNAM} SHARED ${SOURCES_LIB})

# Installation
install(TARGETS ${LIBSTUB_GETPWNAM}
        LIBRARY DESTINATION lib/security)
