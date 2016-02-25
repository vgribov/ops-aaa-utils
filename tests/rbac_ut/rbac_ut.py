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
# Module: rbac_ut.py
# Description: Unit Test for RBAC interface
# =======================================================
import rbac
import time
import subprocess
import os

#
# Used to create user accounts
#
GROUP_OPS_ADMIN = "ops_admin"
GROUP_OPS_NETOP = "ops_netop"
GROUP_NONE = "users"

#
# Users
#
USER_ROOT = "root"
USER_ADMIN_BI = "admin"
USER_NETOP_BI = "netop"
USER_ADMIN = "rbactest_admin"
USER_NETOP = "rbactest_netop"
USER_GENERIC = "rbactest_generic"
USER_BOTH = "rbactest_both"
USER_BOGUS = "I_DONT_EXIST"
USER_BLANK = ""
USER_NETOP_SHORT = "neto"
USER_NETOP_LONG = "netopp"
USER_ADMIN_SHORT = "adm"
USER_ADMIN_LONG = "adminn"

#
# Global test variables
#
passed_tests = 0
failed_tests = 0


#
# These four function do a bulk of the work calling the rbac interfaces
# and making sure we receive the expected results. The expected results
# are passed in from the individual test cases.
#
# The print statements in these routines have been commented out and
# my be useful to un-comment when tracking down failing tests.
#
# Returning a 0 is a passing test case
# Returning a 1 is a failing test case
#
def rbac_ut_rbac_get_user_role(username, role):

    # print "---Checking role ", username
    rbacrole = rbac.get_user_role(username)
    if role not in rbacrole:
        # print "role is", role
        # print "rbacrole is", rbacrole
        # print "===Checking user role - failed"
        return(1)
    # print "   Checking user role - passed"
    return(0)


def rbac_ut_rbac_check_user_permission(username, permission, expected_result):
    # print "---Checking user permission", permission, "for user",\
    # username, "for result", expected_result
    rbacresult = rbac.check_user_permission(username, permission)
    if rbacresult != expected_result:
        # print "===Checking user permission - failed"
        return(1)
    # print "   Checking user permission - passed"
    return(0)


def rbac_ut_rbac_get_user_permissions(username, permissionlist):
    # print "---Getting user permissions for user", username
    rbacpermissions = rbac.get_user_permissions(username)
    permissionlist.sort()
    rbacpermissions.sort()
    result = cmp(permissionlist, rbacpermissions)
    if result == 0:
        # print "   Getting user permission - passed"
        return(0)
    # print "permissionlist", permissionlist
    # print "rbacpermissions", rbacpermissions
    # print "===Getting user permission - failed (lists have different values)"
    return(1)


#
# Creates the user accounts used in both python and C unit tests
#
def create_user_accounts():
    print "---Creating user account ", USER_ADMIN
    cmd = []
    cmd.insert(0, "sudo")
    cmd.insert(1, "/usr/sbin/useradd")
    cmd.insert(2, "-g")
    cmd.insert(3, GROUP_OPS_ADMIN)
    cmd.insert(4, "-s")
    cmd.insert(5, "/sbin/bash")
    cmd.insert(6, USER_ADMIN)
    output = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
    time.sleep(5)

    print "---Creating user account ", USER_NETOP
    cmd.remove(USER_ADMIN)
    cmd = []
    cmd.insert(0, "sudo")
    cmd.insert(1, "/usr/sbin/useradd")
    cmd.insert(2, "-g")
    cmd.insert(3, GROUP_OPS_NETOP)
    cmd.insert(4, "-G")
    cmd.insert(5, "ovsdb-client")
    cmd.insert(6, "-s")
    cmd.insert(7, "/usr/bin/vtysh")
    cmd.insert(8, USER_NETOP)
    output = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
    time.sleep(5)

    print "---Creating user account ", USER_GENERIC
    cmd = []
    cmd.insert(0, "sudo")
    cmd.insert(1, "/usr/sbin/useradd")
    cmd.insert(2, "-g")
    cmd.insert(3, GROUP_NONE)
    cmd.insert(4, "-s")
    cmd.insert(5, "/sbin/bash")
    cmd.insert(6, USER_GENERIC)
    output = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
    time.sleep(5)

    print "---Creating user account ", USER_BOTH
    cmd = []
    cmd.insert(0, "sudo")
    cmd.insert(1, "/usr/sbin/useradd")
    cmd.insert(2, "-g")
    cmd.insert(3, GROUP_OPS_NETOP)
    cmd.insert(4, "-G")
    cmd.insert(5, GROUP_OPS_ADMIN + ",ovsdb-client")
    cmd.insert(6, "-s")
    cmd.insert(7, "/sbin/bash")
    cmd.insert(8, USER_BOTH)
    output = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
    time.sleep(5)


#
# Deletes the user accounts that were used in both python and C testing
#
def delete_user_accounts():
    print "---Deleting user account ", USER_ADMIN
    cmd = []
    cmd.insert(0, "sudo")
    cmd.insert(1, "/usr/sbin/userdel")
    cmd.insert(2, "-r")
    cmd.insert(3, USER_ADMIN)
    output = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
    time.sleep(5)

    print "---Deleting user account ", USER_NETOP
    cmd = []
    cmd.insert(0, "sudo")
    cmd.insert(1, "/usr/sbin/userdel")
    cmd.insert(2, "-r")
    cmd.insert(3, USER_NETOP)
    output = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
    time.sleep(5)

    print "---Deleting user account ", USER_GENERIC
    cmd = []
    cmd.insert(0, "sudo")
    cmd.insert(1, "/usr/sbin/userdel")
    cmd.insert(2, "-r")
    cmd.insert(3, USER_GENERIC)
    output = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
    time.sleep(5)

    print "---Deleting user account ", USER_BOTH
    cmd = []
    cmd.insert(0, "sudo")
    cmd.insert(1, "/usr/sbin/userdel")
    cmd.insert(2, "-r")
    cmd.insert(3, USER_BOTH)
    output = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE)
    time.sleep(5)

#
# These are the individual test cases. I have tried to structure then
# so they closely match the unittest test cases for the "C" shared library.
#


#
# Test the rbac.get_user_role() interface
#
def rbac_get_user_role_multiple_users():

    global failed_tests
    global passed_tests

    print "[ RUN      ]  rbac_get_user_role_multiple_users"

    tf = 0
    tf += rbac_ut_rbac_get_user_role(USER_ROOT, rbac.ROLE_ROOT)
    tf += rbac_ut_rbac_get_user_role(USER_ADMIN_BI, rbac.ROLE_ADMIN)
    tf += rbac_ut_rbac_get_user_role(USER_NETOP_BI, rbac.ROLE_NETOP)
    tf += rbac_ut_rbac_get_user_role(USER_ADMIN, rbac.ROLE_ADMIN)
    tf += rbac_ut_rbac_get_user_role(USER_NETOP, rbac.ROLE_NETOP)
    tf += rbac_ut_rbac_get_user_role(USER_GENERIC, rbac.ROLE_NONE)
    tf += rbac_ut_rbac_get_user_role(USER_BOGUS, "")
    tf += rbac_ut_rbac_get_user_role(USER_BLANK, "")
    tf += rbac_ut_rbac_get_user_role(USER_BOTH, "")
    tf += rbac_ut_rbac_get_user_role(USER_ADMIN_SHORT, "")
    tf += rbac_ut_rbac_get_user_role(USER_ADMIN_LONG, "")
    tf += rbac_ut_rbac_get_user_role(USER_NETOP_SHORT, "")
    tf += rbac_ut_rbac_get_user_role(USER_NETOP_LONG, "")

    if tf > 0:
        failed_tests += 1
        print "Value of:  ", tf
        print "Expected:  0"
        print "[  FAILED  ]  rbac_get_user_role_multiple_users"
    else:
        passed_tests += 1
        print "[      OK  ]  rbac_get_user_role_multiple_users"


#
# Tests the rbac.check_user_permission() interface
# with built-in root user
#
def rbac_check_user_permission_root():

    global failed_tests
    global passed_tests

    print "[ RUN      ]  rbac_check_user_permission_root"

    tf = 0
    tf += rbac_ut_rbac_check_user_permission(
                       USER_ROOT, rbac.READ_SWITCH_CONFIG, True)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_ROOT, rbac.WRITE_SWITCH_CONFIG, True)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_ROOT, rbac.SYS_MGMT, True)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_ROOT, "", False)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_ROOT, "KJDSFKJDSK", False)

    if tf > 0:
        failed_tests += 1
        print "Value of:  ", tf
        print "Expected:  0"
        print "[  FAILED  ]  rbac_check_user_permission_root"
    else:
        passed_tests += 1
        print "[      OK  ]  rbac_check_user_permission_root"


#
# Tests the rbac.check_user_permission() interface
# with built-in admin user
#
def rbac_check_user_permission_builtin_admin():

    global failed_tests
    global passed_tests

    print "[ RUN      ]  rbac_check_user_permission_builtin_admin"

    tf = 0
    tf += rbac_ut_rbac_check_user_permission(
                       USER_ADMIN_BI, rbac.READ_SWITCH_CONFIG, False)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_ADMIN_BI, rbac.WRITE_SWITCH_CONFIG, False)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_ADMIN_BI, rbac.SYS_MGMT, True)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_ADMIN_BI, "", False)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_ADMIN_BI, "KJDSFKJDSK", False)

    if tf > 0:
        failed_tests += 1
        print "Value of:  ", tf
        print "Expected:  0"
        print "[  FAILED  ]  rbac_check_user_permission_builtin_admin"
    else:
        passed_tests += 1
        print "[      OK  ]  rbac_check_user_permission_builtin_admin"


#
# Tests the rbac.check_user_permission() interface
# with built-in netop user
#
def rbac_check_user_permission_builtin_netop():

    global failed_tests
    global passed_tests

    print "[ RUN      ]  rbac_check_user_permission_builtin_netop"

    tf = 0
    tf += rbac_ut_rbac_check_user_permission(
                       USER_NETOP_BI, rbac.READ_SWITCH_CONFIG, True)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_NETOP_BI, rbac.WRITE_SWITCH_CONFIG, True)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_NETOP_BI, rbac.SYS_MGMT, False)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_NETOP_BI, "", False)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_NETOP_BI, "KJDSFKJDSK", False)

    if tf > 0:
        failed_tests += 1
        print "Value of:  ", tf
        print "Expected:  0"
        print "[  FAILED  ]  rbac_check_user_permission_builtin_netop"
    else:
        passed_tests += 1
        print "[      OK  ]  rbac_check_user_permission_builtin_netop"


#
# Tests the rbac.check_user_permission() interface
# with created user with ops_admin
#
def rbac_check_user_permission_user_ops_admin():

    global failed_tests
    global passed_tests

    print "[ RUN      ]  rbac_check_user_permission_user_ops_admin"

    tf = 0
    tf += rbac_ut_rbac_check_user_permission(
                       USER_ADMIN, rbac.READ_SWITCH_CONFIG, False)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_ADMIN, rbac.WRITE_SWITCH_CONFIG, False)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_ADMIN, rbac.SYS_MGMT, True)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_ADMIN, "", False)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_ADMIN, "KJDSFKJDSK", False)

    if tf > 0:
        failed_tests += 1
        print "Value of:  ", tf
        print "Expected:  0"
        print "[  FAILED  ]  rbac_check_user_permission_user_ops_admin"
    else:
        passed_tests += 1
        print "[      OK  ]  rbac_check_user_permission_user_ops_admin"


#
# Tests the rbac.check_user_permission() interface
# with created user with ops_netop
#
def rbac_check_user_permission_user_ops_netop():

    global failed_tests
    global passed_tests

    print "[ RUN      ]  rbac_check_user_permission_user_ops_netop"

    tf = 0
    tf += rbac_ut_rbac_check_user_permission(
                       USER_NETOP, rbac.READ_SWITCH_CONFIG, True)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_NETOP, rbac.WRITE_SWITCH_CONFIG, True)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_NETOP, rbac.SYS_MGMT, False)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_NETOP, "", False)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_NETOP, "KJDSFKJDSK", False)

    if tf > 0:
        failed_tests += 1
        print "Value of:  ", tf
        print "Expected:  0"
        print "[  FAILED  ]  rbac_check_user_permission_user_ops_netop"
    else:
        passed_tests += 1
        print "[      OK  ]  rbac_check_user_permission_user_ops_netop"


#
# Tests the rbac.check_user_permission() interface
# with created user with no ops role
#
def rbac_check_user_permission_user_generic():

    global failed_tests
    global passed_tests

    print "[ RUN      ]  rbac_check_user_permission_user_generic"

    tf = 0
    tf += rbac_ut_rbac_check_user_permission(
                       USER_GENERIC, rbac.READ_SWITCH_CONFIG, False)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_GENERIC, rbac.WRITE_SWITCH_CONFIG, False)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_GENERIC, rbac.SYS_MGMT, False)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_GENERIC, "", False)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_GENERIC, "KJDSFKJDSK", False)

    global failed_tests
    global passed_tests

    if tf > 0:
        failed_tests += 1
        print "Value of:  ", tf
        print "Expected:  0"
        print "[  FAILED  ]  rbac_check_user_permission_user_generic"
    else:
        passed_tests += 1
        print "[      OK  ]  rbac_check_user_permission_user_generic"


#
# Tests the rbac.check_user_permission() interface
# with unknown user
#
def rbac_check_user_permission_user_bogus():

    global failed_tests
    global passed_tests

    print "[ RUN      ]  rbac_check_user_permission_user_bogus"

    tf = 0
    tf += rbac_ut_rbac_check_user_permission(
                       USER_BOGUS, rbac.READ_SWITCH_CONFIG, False)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_BOGUS, rbac.WRITE_SWITCH_CONFIG, False)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_BOGUS, rbac.SYS_MGMT, False)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_BOGUS, "", False)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_BOGUS, "KJDSFKJDSK", False)

    if tf > 0:
        failed_tests += 1
        print "Value of:  ", tf
        print "Expected:  0"
        print "[  FAILED  ]  rbac_check_user_permission_user_bogus"
    else:
        passed_tests += 1
        print "[      OK  ]  rbac_check_user_permission_user_bogus"


#
# Tests the rbac.check_user_permission() interface
# with blank user name
#
def rbac_check_user_permission_user_blank():

    global failed_tests
    global passed_tests

    print "[ RUN      ]  rbac_check_user_permission_user_blank"

    tf = 0
    tf += rbac_ut_rbac_check_user_permission(
                       USER_BLANK, rbac.READ_SWITCH_CONFIG, False)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_BLANK, rbac.WRITE_SWITCH_CONFIG, False)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_BLANK, rbac.SYS_MGMT, False)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_BLANK, "", False)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_BLANK, "KJDSFKJDSK", False)

    if tf > 0:
        failed_tests += 1
        print "Value of:  ", tf
        print "Expected:  0"
        print "[  FAILED  ]  rbac_check_user_permission_user_blank"
    else:
        passed_tests += 1
        print "[      OK  ]  rbac_check_user_permission_user_blank"


#
# Tests the rbac.check_user_permission() interface
# with a user with both ops_admin and ops_netop role
#
def rbac_check_user_permission_user_multiple_roles():

    global failed_tests
    global passed_tests

    print "[ RUN      ]  rbac_check_user_permission_user_multiple_roles"

    tf = 0
    tf += rbac_ut_rbac_check_user_permission(
                       USER_BOTH, rbac.READ_SWITCH_CONFIG, False)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_BOTH, rbac.WRITE_SWITCH_CONFIG, False)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_BOTH, rbac.SYS_MGMT, True)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_BOTH, "", False)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_BOTH, "KJDSFKJDSK", False)

    if tf > 0:
        failed_tests += 1
        print "Value of:  ", tf
        print "Expected:  0"
        print "[  FAILED  ]  rbac_check_user_permission_user_multiple_roles"
    else:
        passed_tests += 1
        print "[      OK  ]  rbac_check_user_permission_user_multiple_roles"


#
# Tests the rbac.check_user_permission() interface
# with a partial valid user name
#
def rbac_check_user_permission_partial_user_names():

    global failed_tests
    global passed_tests

    print "[ RUN      ]  rbac_check_user_permission_partial_user_name"

    tf = 0
    tf += rbac_ut_rbac_check_user_permission(
                       USER_ADMIN_SHORT, rbac.READ_SWITCH_CONFIG, False)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_ADMIN_SHORT, rbac.WRITE_SWITCH_CONFIG, False)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_ADMIN_SHORT, rbac.SYS_MGMT, False)

    tf += rbac_ut_rbac_check_user_permission(
                       USER_ADMIN_LONG, rbac.READ_SWITCH_CONFIG, False)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_ADMIN_LONG, rbac.WRITE_SWITCH_CONFIG, False)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_ADMIN_LONG, rbac.SYS_MGMT, False)

    tf += rbac_ut_rbac_check_user_permission(
                       USER_NETOP_SHORT, rbac.READ_SWITCH_CONFIG, False)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_NETOP_SHORT, rbac.WRITE_SWITCH_CONFIG, False)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_NETOP_SHORT, rbac.SYS_MGMT, False)

    tf += rbac_ut_rbac_check_user_permission(
                       USER_NETOP_LONG, rbac.READ_SWITCH_CONFIG, False)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_NETOP_LONG, rbac.WRITE_SWITCH_CONFIG, False)
    tf += rbac_ut_rbac_check_user_permission(
                       USER_NETOP_LONG, rbac.SYS_MGMT, False)

    if tf > 0:
        failed_tests += 1
        print "Value of:  ", tf
        print "Expected:  0"
        print "[  FAILED  ]  rbac_check_user_permission_partial_user_names"
    else:
        passed_tests += 1
        print "[      OK  ]  rbac_check_user_permission_partial_user_name"


#
# Tests the rbac.get_user_permissions() interface
# with built-in root user.
#
def rbac_get_user_permissions_user_root():

    global failed_tests
    global passed_tests

    print "[ RUN      ]  rbac_get_user_permissions_user_root"

    tf = 0
    tf += rbac_ut_rbac_get_user_permissions(
                       USER_ROOT, rbac.ROLE_ROOT_PERMISSIONS)

    if tf > 0:
        failed_tests += 1
        print "Value of:  ", tf
        print "Expected:  0"
        print "[  FAILED  ]  rbac_get_user_permissions_user_root"
    else:
        passed_tests += 1
        print "[      OK  ]  rbac_get_user_permissions_user_root"


#
# Tests the rbac.get_user_permissions() interface
# with built-in admin user.
#
def rbac_get_user_permissions_user_builtin_admin():

    global failed_tests
    global passed_tests

    print "[ RUN      ]  rbac_get_user_permissions_user_builtin_admin"

    tf = 0
    tf += rbac_ut_rbac_get_user_permissions(
                       USER_ADMIN_BI, rbac.ROLE_ADMIN_PERMISSIONS)

    if tf > 0:
        failed_tests += 1
        print "Value of:  ", tf
        print "Expected:  0"
        print "[  FAILED  ]  rbac_get_user_permissions_user_builtin_admin"
    else:
        passed_tests += 1
        print "[      OK  ]  rbac_get_user_permissions_user_builtin_admin"


#
# Tests the rbac.get_user_permissions() interface
# with built-in netop user.
#
def rbac_get_user_permissions_user_builtin_netop():

    global failed_tests
    global passed_tests

    print "[ RUN      ]  rbac_get_user_permissions_user_builtin_netop"

    tf = 0
    tf += rbac_ut_rbac_get_user_permissions(
                       USER_NETOP_BI, rbac.ROLE_NETOP_PERMISSIONS)

    if tf > 0:
        failed_tests += 1
        print "Value of:  ", tf
        print "Expected:  0"
        print "[  FAILED  ]  rbac_get_user_permissions_user_builtin_netop"
    else:
        passed_tests += 1
        print "[      OK  ]  rbac_get_user_permissions_user_builtin_netop"


#
# Tests the rbac.get_user_permissions() interface
# using a created user with ops_admin role
#
def rbac_get_user_permissions_user_ops_admin():

    global failed_tests
    global passed_tests

    print "[ RUN      ]  rbac_get_user_permissions_user_ops_admin"

    tf = 0
    tf += rbac_ut_rbac_get_user_permissions(
                       USER_ADMIN, rbac.ROLE_ADMIN_PERMISSIONS)

    if tf > 0:
        failed_tests += 1
        print "Value of:  ", tf
        print "Expected:  0"
        print "[  FAILED  ]  rbac_get_user_permissions_user_ops_admin"
    else:
        passed_tests += 1
        print "[      OK  ]  rbac_get_user_permissions_user_ops_admin"


#
# Tests the rbac.get_user_permissions() interface
# using a created user with ops_netop role
#
def rbac_get_user_permissions_user_ops_netop():

    global failed_tests
    global passed_tests

    print "[ RUN      ]  rbac_get_user_permissions_user_ops_netop"

    tf = 0
    tf += rbac_ut_rbac_get_user_permissions(
                       USER_NETOP, rbac.ROLE_NETOP_PERMISSIONS)

    if tf > 0:
        failed_tests += 1
        print "Value of:  ", tf
        print "Expected:  0"
        print "[  FAILED  ]  rbac_get_user_permissions_user_ops_netop"
    else:
        passed_tests += 1
        print "[      OK  ]  rbac_get_user_permissions_user_ops_netop"


#
# Tests the rbac.get_user_permissions() interface
# using a created user with no ops role
#
def rbac_get_user_permissions_user_generic():

    global failed_tests
    global passed_tests

    print "[ RUN      ]  rbac_get_user_permissions_user_generic"

    tf = 0
    tf += rbac_ut_rbac_get_user_permissions(
                       USER_GENERIC, rbac.ROLE_NONE_PERMISSIONS)

    if tf > 0:
        failed_tests += 1
        print "Value of:  ", tf
        print "Expected:  0"
        print "[  FAILED  ]  rbac_get_user_permissions_user_generic"
    else:
        passed_tests += 1
        print "[      OK  ]  rbac_get_user_permissions_user generic"


#
# Tests the rbac.get_user_permissions() interface
# using a bogus user name
#
def rbac_get_user_permissions_user_bogus():

    global failed_tests
    global passed_tests

    print "[ RUN      ]  rbac_get_user_permissions_user_bogus"

    tf = 0
    tf += rbac_ut_rbac_get_user_permissions(USER_BOGUS,
                                            rbac.ROLE_NONE_PERMISSIONS)

    if tf > 0:
        failed_tests += 1
        print "Value of:  ", tf
        print "Expected:  0"
        print "[  FAILED  ]  rbac_get_user_permissions_user_bogus"
    else:
        passed_tests += 1
        print "[      OK  ]  rbac_get_user_permissions_user bogus"


#
# Tests the rbac.get_user_permissions() interface
# using a blank user name
#
def rbac_get_user_permissions_user_blank():

    global failed_tests
    global passed_tests

    print "[ RUN      ]  rbac_get_user_permissions_user_blank"

    tf = 0
    tf += rbac_ut_rbac_get_user_permissions(USER_BLANK,
                                            rbac.ROLE_NONE_PERMISSIONS)

    if tf > 0:
        failed_tests += 1
        print "Value of:  ", tf
        print "Expected:  0"
        print "[  FAILED  ]  rbac_get_user_permissions_user_blank"
    else:
        passed_tests += 1
        print "[      OK  ]  rbac_get_user_permissions_user_blank"


#
# Tests the rbac.get_user_permissions() interface
# using a created user with both ops_admin and ops_netop role
#
def rbac_get_user_permissions_user_multiple_roles():

    global failed_tests
    global passed_tests

    print "[ RUN      ]  rbac_get_user_permissions_user_multiple_roles"

    tf = 0
    tf += rbac_ut_rbac_get_user_permissions(
                       USER_BOTH, rbac.ROLE_ADMIN_PERMISSIONS)

    if tf > 0:
        failed_tests += 1
        print "Value of:  ", tf
        print "Expected:  0"
        print "[  FAILED  ]  rbac_get_user_permissions_user_multiple_roles"
    else:
        passed_tests += 1
        print "[      OK  ]  rbac_get_user_permissions_user_mulitple_roles "


#
# Tests the rbac.get_user_permissions() interface
# using a partial built-in user name
#
def rbac_get_user_permissions_partial_user_names():

    global failed_tests
    global passed_tests

    print "[ RUN      ]  rbac_get_user_permissions_partial_user_names"

    tf = 0
    tf += rbac_ut_rbac_get_user_permissions(
                       USER_ADMIN_SHORT, rbac.ROLE_NONE_PERMISSIONS)
    tf += rbac_ut_rbac_get_user_permissions(
                       USER_ADMIN_LONG, rbac.ROLE_NONE_PERMISSIONS)

    tf += rbac_ut_rbac_get_user_permissions(
                       USER_NETOP_SHORT, rbac.ROLE_NONE_PERMISSIONS)
    tf += rbac_ut_rbac_get_user_permissions(
                       USER_NETOP_LONG, rbac.ROLE_NONE_PERMISSIONS)

    if tf > 0:
        failed_tests += 1
        print "Value of:  ", tf
        print "Expected:  0"
        print "[  FAILED  ]  rbac_get_user_permissions_parital_user_names"
    else:
        passed_tests += 1
        print "[      OK  ]  rbac_get_user_permissions_partial_user_names"


#
# This is the main function that will run all the RBAC Python unit tests.
#
def rbac_ut():
    #
    #   Setup
    #

    # print "Creating user accounts"
    # create_user_accounts()

    print ""
    print ""
    print "rbac_ut Test Harness for python libraries"
    print "[==========]"
    print "[----------]"

#
# Run the python unit tests
#
    print "[----------]"
    print "Running rbac.check_user_permissions() tests"

    #
    # get_user_role tests
    #
    rbac_get_user_role_multiple_users()

    #
    # check user permission tests
    #
    rbac_check_user_permission_root()
    rbac_check_user_permission_builtin_admin()
    rbac_check_user_permission_builtin_netop()
    rbac_check_user_permission_user_ops_admin()
    rbac_check_user_permission_user_ops_netop()
    rbac_check_user_permission_user_generic()
    rbac_check_user_permission_user_bogus()
    rbac_check_user_permission_user_blank()
    rbac_check_user_permission_user_multiple_roles()
    rbac_check_user_permission_partial_user_names()

    #
    # get user permissions tests
    #
    rbac_get_user_permissions_user_root()
    rbac_get_user_permissions_user_builtin_admin()
    rbac_get_user_permissions_user_builtin_netop()
    rbac_get_user_permissions_user_ops_admin()
    rbac_get_user_permissions_user_ops_netop()
    rbac_get_user_permissions_user_generic()
    rbac_get_user_permissions_user_bogus()
    rbac_get_user_permissions_user_blank()
    rbac_get_user_permissions_user_multiple_roles()
    rbac_get_user_permissions_partial_user_names()

    #
    # Results
    #
    print "[----------] ", passed_tests + failed_tests, "from rbac_ut"
    print ""
    print "[==========] ", passed_tests + failed_tests, "from rbac_ut"
    if passed_tests > 0:
        print "[  PASSED  ] ", passed_tests
    if failed_tests > 0:
        print "[  FAILED  ] ", failed_tests
    print ""
    print ""

    #
    # Teardown
    #

    # print "Deleting user accounts"
    # delete_user_accounts()

    return(0)
