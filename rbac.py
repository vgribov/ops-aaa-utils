#!/usr/bin/env python
# Copyright (C) 2016 Hewlett Packard Enterprise Development LP
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

# =======================================================
# Module: rbac.py
# Description: Provides API's to RBAC authorization routines
# =======================================================

# =============================================
#  Boolean check_user_permission(username, permission)
#
#  Example_usage of check_user_permission(username, permission):
#    ......
#    result = check_user_permission("user", rbac.READ_SWITCH_CONFIG)
#    if result == True:
#        /* User has read access to the Switch configuration information */
#        ...
#    ......
#
# List get_user_permissions(username)
#
#   Example_usage of get_user_permissions(username):
#     ......
#     permission_list = check_user_permission("user")
#     ......
#     if rbac.READ_SWITCH_CONFIG in permissions_list:
#       /* User has read access to the Switch configuration information */
#       ...
#    ......
#    if rbac.SYS_MGMT in permissions_list:
#       /* User has access to modify system management */
#      ...
#
# =============================================
import subprocess
import os

#
# Supported Roles
#
ROLE_ADMIN = "ops_admin"
ROLE_NETOP = "ops_netop"
ROLE_NONE = "none"

#
# Supported Permissions
#
READ_SWITCH_CONFIG = "READ_SWITCH_CONFIG"
WRITE_SWITCH_CONFIG = "WRITE_SWITCH_CONFIG"
SYS_MGMT = "SYS_MGMT"

#
# Permission list for each supported Role
#
ROLE_ADMIN_PERMISSIONS = [SYS_MGMT]

ROLE_NETOP_PERMISSIONS = [READ_SWITCH_CONFIG, WRITE_SWITCH_CONFIG]

ROLE_NONE_PERMISSIONS = []

#
# Globably callable functions to support RBAC.
#


def check_user_permission(username, permission):
    '''
    This function will return True or False depending if the user has access
    to the permission.
    '''
    if permission == READ_SWITCH_CONFIG:
        return True
    if permission == WRITE_SWITCH_CONFIG:
        return True
    return False


def get_user_permissions(username):
    '''
    This function will return a list of permission the user has access to.
    A empty list will be returned if the user has no permissions.
    '''
    permissions = []
    permissions.append(READ_SWITCH_CONFIG)
    permissions.append(WRITE_SWITCH_CONFIG)
    return permissions


def get_user_role(username):
    '''
    This function will return a string containing the role of the user.
    If the user has no role, it will return the string "none".
    '''
    return ROLE_NETOP
