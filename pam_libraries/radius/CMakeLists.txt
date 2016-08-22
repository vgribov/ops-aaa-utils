# This is free and unencumbered software released into the public domain.
#
# Anyone is free to copy, modify, publish, use, compile, sell, or
# distribute this software, either in source code form or as a compiled
# binary, for any purpose, commercial or non-commercial, and by any
# means.
#
# In jurisdictions that recognize copyright laws, the author or authors
# of this software dedicate any and all copyright interest in the
# software to the public domain. We make this dedication for the benefit
# of the public at large and to the detriment of our heirs and
# successors. We intend this dedication to be an overt act of
# relinquishment in perpetuity of all present and future rights to this
# software under copyright law.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
# IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY CLAIM, DAMAGES OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
# ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
# OTHER DEALINGS IN THE SOFTWARE.
#
# For more information, please refer to <http://unlicense.org>

cmake_minimum_required(VERSION 2.8)

project ("pam_radius")

set (LIBPAM_RADIUS pam_radius)
set (LIBPAM_RADIUS_STATIC pam_radius_s)
set (LIBPAM_RADIUS_CHAP pam_radius_chap)
set (LIBPAM_RADIUS_CHAP_STATIC pam_radius_chap_s)

include(GNUInstallDirs)
include(FindPkgConfig)

add_definitions(-DSYSCONFDIR="${CMAKE_INSTALL_SYSCONFDIR}")

set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -Wall -Werror -DFTR_PROXY_ARP -DFTR_LOCAL_PROXY_ARP -DHAVE_LIBCRYPTO -DHAVE_OPENSSL_MD5_H")

include_directories(
  ${CMAKE_SOURCE_DIR}
  ${CMAKE_SOURCE_DIR}/pam_libraries/radius/
  ${PROJECT_SOURCE_DIR}
  ${PROJECT_BINARY_DIR}
  ${PROJECT_SOURCE_DIR}/${INCL_DIR}
  )

# PAM libraries source files
set (SOURCES_LIB_PAM_RADIUS
  src/pam_radius_auth.c
  src/md5.c
    )

add_library (${LIBPAM_RADIUS} SHARED ${SOURCES_LIB_PAM_RADIUS})

target_link_libraries(${LIBPAM_RADIUS}
  util crypt pthread readline audit opsutils crypto pam pam_misc )

install(TARGETS ${LIBPAM_RADIUS}
        LIBRARY DESTINATION lib/security
       )

set (CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DUSE_CHAP")

add_library (${LIBPAM_RADIUS_CHAP} SHARED ${SOURCES_LIB_PAM_RADIUS})

target_link_libraries(${LIBPAM_RADIUS_CHAP}
  util crypt pthread readline audit opsutils crypto pam pam_misc )

install(TARGETS ${LIBPAM_RADIUS_CHAP}
        LIBRARY DESTINATION lib/security
       )
