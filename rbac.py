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

import subprocess
import os

#
# Supported Roles
#
ROLE_ROOT = "root"
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
ROLE_ROOT_PERMISSIONS = [SYS_MGMT, READ_SWITCH_CONFIG, WRITE_SWITCH_CONFIG]
ROLE_ADMIN_PERMISSIONS = [SYS_MGMT]
ROLE_NETOP_PERMISSIONS = [READ_SWITCH_CONFIG, WRITE_SWITCH_CONFIG]
ROLE_NONE_PERMISSIONS = []


#
# Locally callable functions.
#
def get_groups(username):
    '''
    This function returns all the groups the user is in. If the user has
    no groups (does_not_exist) it will return an empty list.
    '''
    grouplist = []
    cmd = []
    cmd.insert(0, "groups")
    cmd.insert(1, username)
    groups = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
    for group in groups.stdout.readlines():
        if "groups: unknown user" in group:
            return(grouplist)
        grouplist = group.split()
        return(grouplist)


def get_permissions(role):
    '''
    This function returns the list of permission based on the users role
    '''
    if ROLE_ROOT in role:
        return ROLE_ROOT_PERMISSIONS
    if ROLE_ADMIN in role:
        return ROLE_ADMIN_PERMISSIONS
    if ROLE_NETOP in role:
        return ROLE_NETOP_PERMISSIONS
    return ROLE_NONE_PERMISSIONS


def get_role(groups):
    '''
    This function returns users role based
    '''
    if ROLE_ROOT in groups:
        return ROLE_ROOT
    if ROLE_ADMIN in groups:
        return ROLE_ADMIN
    if ROLE_NETOP in groups:
        return ROLE_NETOP
    return ROLE_NONE


#
# Globably callable functions to support RBAC.
#
def check_user_permission(username, permission):
    '''
    This function will return True or False depending if the user has access
    to the permission.
    '''
    groups = get_groups(username)
    if not groups:
        return False
    role = get_role(groups)
    if not role:
        return False
    permissions = get_permissions(role)
    if not permissions:
        return False
    if permission in permissions:
        return True
    return False


def get_user_permissions(username):
    '''
    This function will return a list of permission the user has access to.
    A empty list will be returned if the user has no permissions.
    '''
    permissions = []
    groups = get_groups(username)
    if not groups:
        return permissions
    role = get_role(groups)
    if not role:
        return permissions
    permissions = get_permissions(role)
    return permissions


def get_user_role(username):
    '''
    This function will return a string containing the role of the user.
    If the user has no role, it will return the string "none".
    '''
    groups = get_groups(username)
    if not groups:
        return ROLE_NONE
    role = get_role(groups)
    if not role:
        return ROLE_NONE
    return role


#
# Support functions for automated component testing.
#
def check_user_permission_p(username, permission):
    result = check_user_permission(username, permission)
    print result


def get_user_permissions_p(username):
    result = get_user_permissions(username)
    print result


def get_user_role_p(username):
    result = get_user_role(username)
    print result
