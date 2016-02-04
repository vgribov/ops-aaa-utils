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

set (RBAC_LIB rbac)
project (${RBAC_LIB})
set (INCL_DIR ${CMAKE_SOURCE_DIR}/include)

# libraries source files
set (SOURCES ${PROJECT_SOURCE_DIR}/rbac.c)

include_directories (${INCL_DIR} ${PROJECT_SOURCE_DIR})

# Rules to build libaray
add_library (${RBAC_LIB} SHARED ${SOURCES})

target_link_libraries (${RBAC_LIB} -lpthread -lrt)

# Define compile flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -Wall -Werror")

set(OPS_U_VER_MAJOR "0")
set(OPS_U_VER_MINOR "1")
set(OPS_U_VER_PATCH "0")
set(RBAC_VERSION "${OPS_U_VER_MAJOR}.${OPS_U_VER_MINOR}.${OPS_U_VER_PATCH}")
set_target_properties(${RBAC_LIB} PROPERTIES VERSION ${RBAC_VERSION})

configure_file(${PROJECT_SOURCE_DIR}/rbac.pc.in ${PROJECT_SOURCE_DIR}/rbac.pc @ONLY)

# Installation
install(TARGETS ${RBAC_LIB}
        ARCHIVE DESTINATION lib
        LIBRARY DESTINATION lib
       )

install(FILES ${INCL_DIR}/rbac.h DESTINATION include)
