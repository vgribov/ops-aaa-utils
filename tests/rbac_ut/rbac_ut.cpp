 /*
 * Copyright 2016 Hewlett Packard Enterprise Development LP
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License. You may obtain
 *  a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *  License for the specific language governing permissions and limitations
 *  under the License.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <stdbool.h>
#include <unistd.h>
#include <grp.h>
#include <rbac.h>
#include <gtest/gtest.h>

/*
 * The currently supported roles.
 */

/*
 * The user we will used during out testing.
 *    The first tree users are built in by default.
 *    The next four (rbactest_xxx) need to be create (by run_rbac_ut)
 *    The next three users are non-existant.
 *    The final four users are partial usernames
 */
const char *USER_ROOT = "root";
const char *USER_ADMIN_BI = "admin";
const char *USER_NETOP_BI = "netop";
const char *USER_ADMIN = "rbactest_admin";
const char *USER_NETOP = "rbactest_netop";
const char *USER_GENERIC = "rbactest_generic";
const char *USER_BOTH = "rbactest_both";
const char *USER_BOGUS = "I_DONT_EXIST";
const char *USER_BLANK = "";
const char *USER_NULL = NULL;
const char *USER_NETOP_SHORT = "neto";
const char *USER_NETOP_LONG = "netopp";
const char *USER_ADMIN_SHORT = "adm";
const char *USER_ADMIN_LONG = "adminn";

#define TEST_PASSED     0
#define TEST_FAILED     1

/*
 * If you want to dump a lot of debugging information while running the
 * unit tests, just define SHOW_DETAILS below.
 */
#undef SHOW_DETAIL_TESTS
#undef  SHOW_DETAIL_TESTCASES

/*
 * rbac_test_rbac_get_user_role()
 */
int
rbac_test_rbac_get_user_role(const char *username,
                             const char *rolename,
                             bool expected_rbac_result,
                             bool expected_compare_result)
{
    bool          rbac_result;
    rbac_role_t   role;

#ifdef SHOW_DETAIL_TESTS
    printf("---Checking role %s user %s rbac result %d compare result %d \n",
           rolename, username, expected_rbac_result, expected_compare_result);
#endif

    rbac_result = rbac_get_user_role(username, &role);
    if (expected_rbac_result == false) {
       if (rbac_result != expected_rbac_result) {
#ifdef SHOW_DETAIL_TESTS
          printf("===Checking role - failed\n");
#endif
          return(TEST_FAILED);
          }
       else {
#ifdef SHOW_DETAIL_TESTS
          printf("   Checking role - passed\n");
#endif
          return(TEST_PASSED);
          }
       }

    if (strncmp(rolename, role.name, RBAC_MAX_ROLE_NAME_LEN) == 0)  {
       if (expected_compare_result) {
#ifdef SHOW_DETAIL_TESTS
          printf("   Checking role - passed\n");
#endif
          return(TEST_PASSED);
          }
      else {
#ifdef SHOW_DETAILS_TESTS
         printf("===Checking role - failed\n");
#endif
         return(TEST_FAILED);
         }
       }

    if (expected_compare_result) {
#ifdef SHOW_DETAIL_TESTS
       printf("===Checking role - failed\n");
#endif
       return(TEST_FAILED);
       }
    else {
#ifdef SHOW_DETAIL_TESTS
       printf("   Checking role - passed\n");
#endif
       return(TEST_PASSED);
       }
}

/*
 * rbac_test_rbac_check_user_permission()
 */
int
rbac_test_rbac_check_user_permission(const char *username,
                                     const char *permission,
                                     bool expected_rbac_result)
{
    bool         rbac_result;

#ifdef SHOW_DETAIL_TESTS
    printf("---Checking user permission %s user %s rbac result %d \n ",
            permission, username, expected_rbac_result);
#endif

    rbac_result = rbac_check_user_permission(username, permission);
    if (rbac_result != expected_rbac_result) {
#ifdef SHOW_DETAIL_TESTS
        printf("===Checking user permission - failed\n");
#endif
        return(TEST_FAILED);
        }

#ifdef SHOW_DETAIL_TESTS
    printf("   Checking user permission - passed\n");
#endif
    return(TEST_PASSED);
}

/*
 * rbac_test_rbac_get_user_permissions
 */
int
rbac_test_rbac_get_user_permissions(const char *username,
                                    const char *permission,
                                    bool expected_rbac_result,
                                    bool expected_compare_result)
{
    int                   i;
    bool                  rbac_result;
    rbac_permissions_t    permissions;

#ifdef SHOW_DETAIL_TESTS
    printf("---Check permission %s user %s rbac result %d compare result %d \n ",
          permission, username, expected_rbac_result, expected_compare_result);
#endif

    rbac_result = rbac_get_user_permissions(username, &permissions);
    if (expected_rbac_result == false) {
       if (rbac_result != expected_rbac_result) {
#ifdef SHOW_DETAIL_TESTS
           printf("===Checking user permissions - failed\n");
#endif
           return(TEST_FAILED);
           }
        else {
#ifdef SHOW_DETAIL_TESTS
           printf("===Checking user permissions - passed\n");
#endif
           return(TEST_PASSED);
           }
        }

    if (rbac_result) {
       for (i = 0; i < permissions.count; i++) {
           if (strncmp(permission, permissions.name[i],
               RBAC_MAX_PERMISSION_NAME_LEN) == 0) {
              if (expected_compare_result) {
#ifdef SHOW_DETAIL_TESTS
                 printf("   Checking user permissions - passed\n");
#endif
                 return(TEST_PASSED);
                 }
              else {
#ifdef SHOW_DETAIL_TESTS
                 printf("===Checking user permissions - failed\n");
#endif
                 return(TEST_FAILED);
                 }
              }
           }
       }

    if (expected_compare_result) {
#ifdef SHOW_DETAIL_TESTS
       printf("===Checking user permissions - failed\n");
#endif
       return(TEST_FAILED);
       }
    else {
#ifdef SHOW_DETAIL_TESTS
       printf("   Checking user permissions - passed\n");
#endif
       return(TEST_PASSED);
       }
}


/*
 * Start of the test cases. These test cases use
 * gtest.
 *
 */

class rbac_ut : public ::testing::Test {
  protected:
  virtual void SetUp() {
  }

  virtual void TearDown() {
  }

};

/*
 * Tests the rbac_get_user_role() interface
 */
TEST_F(rbac_ut,rbac_get_user_role_multiple_users)
{
    int tf = 0;

#ifdef SHOW_DETAIL_TESTCASES
    printf("\n\nRunning rbac_get_user_role(multiple users) tests\n");
#endif

    tf += rbac_test_rbac_get_user_role(USER_ROOT, RBAC_ROLE_ROOT,
                         true, true);
    tf += rbac_test_rbac_get_user_role(USER_ADMIN_BI, RBAC_ROLE_ADMIN,
                         true, true);
    tf += rbac_test_rbac_get_user_role(USER_NETOP_BI, RBAC_ROLE_NETOP,
                         true, true);
    tf += rbac_test_rbac_get_user_role(USER_ADMIN, RBAC_ROLE_ADMIN,
                         true, true);
    tf += rbac_test_rbac_get_user_role(USER_NETOP, RBAC_ROLE_NETOP,
                         true, true);
    tf += rbac_test_rbac_get_user_role(USER_GENERIC, RBAC_ROLE_NONE,
                         true, true);
    tf += rbac_test_rbac_get_user_role(USER_BOGUS, RBAC_ROLE_NONE,
                         true, true);
    tf += rbac_test_rbac_get_user_role(USER_BLANK, RBAC_ROLE_NONE,
                         true,  true);
    tf += rbac_test_rbac_get_user_role(USER_NULL, RBAC_ROLE_NONE,
                         false, false);
    tf += rbac_test_rbac_get_user_role(USER_BOTH, RBAC_ROLE_ADMIN,
                         true, true);
    tf += rbac_test_rbac_get_user_role(USER_NETOP_SHORT, RBAC_ROLE_NONE,
                         true, true);
    tf += rbac_test_rbac_get_user_role(USER_NETOP_LONG, RBAC_ROLE_NONE,
                         true, true);
    tf += rbac_test_rbac_get_user_role(USER_ADMIN_SHORT, RBAC_ROLE_NONE,
                         true, true);
    tf += rbac_test_rbac_get_user_role(USER_ADMIN_LONG, RBAC_ROLE_NONE,
                         true, true);

    EXPECT_EQ(0,tf);
}

/*
 * Tests the rbac_check_user_permission() interface
 * with built-in root user.
 */
TEST_F(rbac_ut,rbac_check_user_permission_user_root)
{
    int tf = 0;

#ifdef SHOW_DETAIL_TESTCASES
    printf("\n\nRunning rbac_check_user_permission(user root) tests\n");
#endif

    tf += rbac_test_rbac_check_user_permission(USER_ROOT,
                         RBAC_READ_SWITCH_CONFIG, true);
    tf += rbac_test_rbac_check_user_permission(USER_ROOT,
                         RBAC_WRITE_SWITCH_CONFIG, true);
    tf += rbac_test_rbac_check_user_permission(USER_ROOT,
                         RBAC_SYS_MGMT, true);
    tf += rbac_test_rbac_check_user_permission(USER_ROOT,
                         "", false);
    tf += rbac_test_rbac_check_user_permission(USER_ROOT,
                         "KJDSFKJDSK", false);

    EXPECT_EQ(0,tf);
}

/*
 * Tests the rbac_check_user_permission() interface
 * with built-in admin user.
 */
TEST_F(rbac_ut,rbac_check_user_permission_builtin_admin)
{
    int tf = 0;

#ifdef SHOW_DETAIL_TESTCASES
    printf("\n\nRunning rbac_check_user_permission(builtin user admin) tests\n");
#endif

    tf += rbac_test_rbac_check_user_permission(USER_ADMIN_BI,
                         RBAC_READ_SWITCH_CONFIG, false);
    tf += rbac_test_rbac_check_user_permission(USER_ADMIN_BI,
                         RBAC_WRITE_SWITCH_CONFIG, false);
    tf += rbac_test_rbac_check_user_permission(USER_ADMIN_BI,
                         RBAC_SYS_MGMT, true);
    tf += rbac_test_rbac_check_user_permission(USER_ADMIN_BI,
                         "", false);
    tf += rbac_test_rbac_check_user_permission(USER_ADMIN_BI,
                         "KJDSFKJDSK", false);

    EXPECT_EQ(0,tf);
}

/*
 * Tests the rbac_check_user_permission() interface
 * with built-in netop user.
 */
TEST_F(rbac_ut,rbac_check_user_permission_builtin_netop)
{
    int tf = 0;

#ifdef SHOW_DETAIL_TESTCASES
    printf("\n\nRunning rbac_check_user_permission(builtin user netop) tests\n");
#endif

    tf += rbac_test_rbac_check_user_permission(USER_NETOP_BI,
                         RBAC_READ_SWITCH_CONFIG, true);
    tf += rbac_test_rbac_check_user_permission(USER_NETOP_BI,
                         RBAC_WRITE_SWITCH_CONFIG, true);
    tf += rbac_test_rbac_check_user_permission(USER_NETOP_BI,
                         RBAC_SYS_MGMT, false);
    tf += rbac_test_rbac_check_user_permission(USER_NETOP_BI,
                          "", false);
    tf += rbac_test_rbac_check_user_permission(USER_NETOP_BI,
                         "KJDSFKJDSK", false);

    EXPECT_EQ(0,tf);
}

/*
 * Tests the rbac_check_user_permission() interface
 * with created user with ops_admin role.
 */
TEST_F(rbac_ut,rbac_check_user_permission_user_ops_admin)
{
    int tf = 0;

#ifdef SHOW_DETAIL_TESTCASES
    printf("\n\nRunning rbac_check_user_permission(user ops_admin) tests\n");
#endif

    tf += rbac_test_rbac_check_user_permission(USER_ADMIN,
                         RBAC_READ_SWITCH_CONFIG, false);
    tf += rbac_test_rbac_check_user_permission(USER_ADMIN,
                         RBAC_WRITE_SWITCH_CONFIG, false);
    tf += rbac_test_rbac_check_user_permission(USER_ADMIN,
                         RBAC_SYS_MGMT, true);
    tf += rbac_test_rbac_check_user_permission(USER_ADMIN,
                         "", false);
    tf += rbac_test_rbac_check_user_permission(USER_ADMIN,
                        "KJDSFKJDSK", false);

    EXPECT_EQ(0,tf);
}

/*
 * Tests the rbac_check_user_permission() interface
 * with created user with ops_netop role.
 */
TEST_F(rbac_ut,rbac_check_user_permission_user_ops_netop)
{
    int tf = 0;

#ifdef SHOW_DETAIL_TESTCASES
    printf("\n\nRunning rbac_check_user_permission(user ops_netop) tests\n");
#endif

    tf += rbac_test_rbac_check_user_permission(USER_NETOP,
                         RBAC_READ_SWITCH_CONFIG, true);
    tf += rbac_test_rbac_check_user_permission(USER_NETOP,
                         RBAC_WRITE_SWITCH_CONFIG, true);
    tf += rbac_test_rbac_check_user_permission(USER_NETOP,
                         RBAC_SYS_MGMT, false);
    tf += rbac_test_rbac_check_user_permission(USER_NETOP,
                         "", false);
    tf += rbac_test_rbac_check_user_permission(USER_NETOP,
                         "KJDSFKJDSK", false);

    EXPECT_EQ(0,tf);
}

/*
 * Tests the rbac_check_user_permission() interface
 * with created user no ops role.
 */
TEST_F(rbac_ut,rbac_check_user_permission_user_generic)
{
    int tf = 0;

#ifdef SHOW_DETAIL_TESTCASES
    printf("\n\nRunning rbac_check_user_permission(user generic) tests\n");
#endif

    tf += rbac_test_rbac_check_user_permission(USER_GENERIC,
                         RBAC_READ_SWITCH_CONFIG, false);
    tf += rbac_test_rbac_check_user_permission(USER_GENERIC,
                         RBAC_WRITE_SWITCH_CONFIG, false);
    tf += rbac_test_rbac_check_user_permission(USER_GENERIC,
                         RBAC_SYS_MGMT, false);
    tf += rbac_test_rbac_check_user_permission(USER_GENERIC,
                         "", false);
    tf += rbac_test_rbac_check_user_permission(USER_GENERIC,
                         "KJDSFKJDSK", false);

    EXPECT_EQ(0,tf);
}

/*
 * Tests the rbac_check_user_permission() interface
 * with unknown user.
 */
TEST_F(rbac_ut,rbac_check_user_permission_user_bogus)
{
    int tf = 0;

#ifdef SHOW_DETAIL_TESTCASES
    printf("\n\nRunning rbac_check_user_permission(user bogus) tests\n");
#endif

    tf += rbac_test_rbac_check_user_permission(USER_BOGUS,
                         RBAC_READ_SWITCH_CONFIG, false);
    tf += rbac_test_rbac_check_user_permission(USER_BOGUS,
                         RBAC_WRITE_SWITCH_CONFIG, false);
    tf += rbac_test_rbac_check_user_permission(USER_BOGUS,
                         RBAC_SYS_MGMT, false);
    tf += rbac_test_rbac_check_user_permission(USER_BOGUS,
                         "", false);
    tf += rbac_test_rbac_check_user_permission(USER_BOGUS,
                         "KJDSFKJDSK", false);

    EXPECT_EQ(0,tf);
}

/*
 * Tests the rbac_check_user_permission() interface
 * with a blank user name.
 */
TEST_F(rbac_ut,rbac_check_user_permission_user_blank)
{
    int tf = 0;

#ifdef SHOW_DETAIL_TESTCASES
    printf("\n\nRunning rbac_check_user_permission(user blank) tests\n");
#endif

    tf += rbac_test_rbac_check_user_permission(USER_BLANK,
                         RBAC_READ_SWITCH_CONFIG, false);
    tf += rbac_test_rbac_check_user_permission(USER_BLANK,
                         RBAC_WRITE_SWITCH_CONFIG, false);
    tf += rbac_test_rbac_check_user_permission(USER_BLANK,
                         RBAC_SYS_MGMT, false);
    tf += rbac_test_rbac_check_user_permission(USER_BLANK,
                         "", false);
    tf += rbac_test_rbac_check_user_permission(USER_BLANK,
                         "KJDSFKJDSK", false);

    EXPECT_EQ(0,tf);
}

/*
 * Tests the rbac_check_user_permission() interface
 * with a null user name.
 */
TEST_F(rbac_ut,rbac_check_user_permission_user_null)
{
    int tf = 0;

#ifdef SHOW_DETAIL_TESTCASES
    printf("\n\nRunning rbac_check_user_permission(user null) tests\n");
#endif

    tf += rbac_test_rbac_check_user_permission(USER_NULL,
                         RBAC_READ_SWITCH_CONFIG, false);
    tf += rbac_test_rbac_check_user_permission(USER_NULL,
                         RBAC_WRITE_SWITCH_CONFIG, false);
    tf += rbac_test_rbac_check_user_permission(USER_NULL,
                         RBAC_SYS_MGMT, false);
    tf += rbac_test_rbac_check_user_permission(USER_NULL,
                         "", false);
    tf += rbac_test_rbac_check_user_permission(USER_NULL,
                         "KJDSFKJDSK", false);

    EXPECT_EQ(0,tf);
}

/*
 * Tests the rbac_check_user_permission() interface
 * with a user with both ops_admin and ops_netop role.
 */
TEST_F(rbac_ut,rbac_check_user_permission_user_multiple_roles)
{
    int tf = 0;

#ifdef SHOW_DETAIL_TESTCASES
    printf("\n\nRunning rbac_check_user_permission(user multiple_roles) tests\n");
#endif

    tf += rbac_test_rbac_check_user_permission(USER_BOTH,
                         RBAC_READ_SWITCH_CONFIG, false);
    tf += rbac_test_rbac_check_user_permission(USER_BOTH,
                         RBAC_WRITE_SWITCH_CONFIG, false);
    tf += rbac_test_rbac_check_user_permission(USER_BOTH,
                         RBAC_SYS_MGMT, true);
    tf += rbac_test_rbac_check_user_permission(USER_BOTH,
                         "", false);
    tf += rbac_test_rbac_check_user_permission(USER_BOTH,
                         "KJDSFKJDSK", false);

    EXPECT_EQ(0,tf);
}

/*
 * Tests the rbac_check_user_permission() interface
 * with a partial valid user name.
 */
TEST_F(rbac_ut,rbac_check_user_permission_partial_user_names)
{
    int tf = 0;

#ifdef SHOW_DETAIL_TESTCASES
    printf("\n\nRunning rbac_check_user_permission(partial user names) tests\n");
#endif

    tf += rbac_test_rbac_check_user_permission(USER_ADMIN_SHORT,
                         RBAC_READ_SWITCH_CONFIG, false);
    tf += rbac_test_rbac_check_user_permission(USER_ADMIN_SHORT,
                         RBAC_WRITE_SWITCH_CONFIG, false);
    tf += rbac_test_rbac_check_user_permission(USER_ADMIN_SHORT,
                         RBAC_SYS_MGMT, false);

    tf += rbac_test_rbac_check_user_permission(USER_ADMIN_LONG,
                         RBAC_READ_SWITCH_CONFIG, false);
    tf += rbac_test_rbac_check_user_permission(USER_ADMIN_LONG,
                         RBAC_WRITE_SWITCH_CONFIG, false);
    tf += rbac_test_rbac_check_user_permission(USER_ADMIN_LONG,
                         RBAC_SYS_MGMT, false);

    tf += rbac_test_rbac_check_user_permission(USER_NETOP_SHORT,
                         RBAC_READ_SWITCH_CONFIG, false);
    tf += rbac_test_rbac_check_user_permission(USER_NETOP_SHORT,
                         RBAC_WRITE_SWITCH_CONFIG, false);
    tf += rbac_test_rbac_check_user_permission(USER_NETOP_SHORT,
                         RBAC_SYS_MGMT, false);

    tf += rbac_test_rbac_check_user_permission(USER_NETOP_LONG,
                         RBAC_READ_SWITCH_CONFIG, false);
    tf += rbac_test_rbac_check_user_permission(USER_NETOP_LONG,
                         RBAC_WRITE_SWITCH_CONFIG, false);
    tf += rbac_test_rbac_check_user_permission(USER_NETOP_LONG,
                         RBAC_SYS_MGMT, false);

    EXPECT_EQ(0,tf);
}

/*
 * Tests the rbac_get_user_permissions() interface
 * with built-in root user.
 */
TEST_F(rbac_ut,rbac_get_user_permissions_user_root)
{
    int tf = 0;

#ifdef SHOW_DETAIL_TESTCASES
    printf("\n\nRunning rbac_get_user_permissions(user root) tests\n");
#endif

    tf += rbac_test_rbac_get_user_permissions(USER_ROOT,
                         RBAC_READ_SWITCH_CONFIG, true, true);
    tf += rbac_test_rbac_get_user_permissions(USER_ROOT,
                         RBAC_WRITE_SWITCH_CONFIG, true, true);
    tf += rbac_test_rbac_get_user_permissions(USER_ROOT,
                         RBAC_SYS_MGMT, true, true);

    EXPECT_EQ(0,tf);
}

/*
 * Tests the rbac_get_user_permissions() interface
 * with built-in admin user.
 */
TEST_F(rbac_ut,rbac_get_user_permissions_user_builtin_admin)
{
    int tf = 0;

#ifdef SHOW_DETAIL_TESTCASES
    printf("\n\nRunning rbac_get_user_permissions(user builtin admin) tests\n");
#endif

    tf += rbac_test_rbac_get_user_permissions(USER_ADMIN_BI,
                             RBAC_READ_SWITCH_CONFIG, true, false);
    tf += rbac_test_rbac_get_user_permissions(USER_ADMIN_BI,
                             RBAC_WRITE_SWITCH_CONFIG, true, false);
    tf += rbac_test_rbac_get_user_permissions(USER_ADMIN_BI,
                             RBAC_SYS_MGMT, true, true);

    EXPECT_EQ(0,tf);
}

/*
 * Tests the rbac_get_user_permissions() interface
 * with built-in netop user.
 */
TEST_F(rbac_ut,rbac_get_user_permissions_user_builtin_netop)
{
    int tf = 0;

#ifdef SHOW_DETAIL_TESTCASES
    printf("\n\nRunning rbac_get_user_permissions(user builtin netop) tests\n");
#endif

    tf += rbac_test_rbac_get_user_permissions(USER_NETOP_BI,
                             RBAC_READ_SWITCH_CONFIG, true, true);
    tf += rbac_test_rbac_get_user_permissions(USER_NETOP_BI,
                             RBAC_WRITE_SWITCH_CONFIG, true, true);
    tf += rbac_test_rbac_get_user_permissions(USER_NETOP_BI,
                             RBAC_SYS_MGMT, true, false);

    EXPECT_EQ(0,tf);
}


/*
 * Tests the rbac_get_user_permissions() interface
 * using a created user with ops_admin role.
 */
TEST_F(rbac_ut,rbac_get_user_permissions_user_ops_admin)
{
    int tf = 0;

#ifdef SHOW_DETAIL_TESTCASES
    printf("\n\nRunning rbac_get_user_permissions(user ops_admin) tests\n");
#endif

    tf += rbac_test_rbac_get_user_permissions(USER_ADMIN,
                             RBAC_READ_SWITCH_CONFIG, true, false);
    tf += rbac_test_rbac_get_user_permissions(USER_ADMIN,
                             RBAC_WRITE_SWITCH_CONFIG, true, false);
    tf += rbac_test_rbac_get_user_permissions(USER_ADMIN,
                             RBAC_SYS_MGMT, true, true);

    EXPECT_EQ(0,tf);
}

/*
 * Tests the rbac_get_user_permissions() interface
 * using a created user with ops_netop role.
 */
TEST_F(rbac_ut,rbac_get_user_permissions_user_ops_netop)
{
    int tf = 0;

#ifdef SHOW_DETAIL_TESTCASES
    printf("\n\nRunning rbac_get_user_permissions(user ops_netop) tests\n");
#endif

    tf += rbac_test_rbac_get_user_permissions(USER_NETOP,
                             RBAC_READ_SWITCH_CONFIG, true, true);
    tf += rbac_test_rbac_get_user_permissions(USER_NETOP,
                             RBAC_WRITE_SWITCH_CONFIG, true, true);
    tf += rbac_test_rbac_get_user_permissions(USER_NETOP,
                             RBAC_SYS_MGMT, true, false);

    EXPECT_EQ(0,tf);
}


/*
 * Tests the rbac_get_user_permissions() interface
 * using a created user with no ops roles.
 */
TEST_F(rbac_ut,rbac_get_user_permissions_user_generic)
{
    int tf = 0;

#ifdef SHOW_DETAIL_TESTCASES
    printf("\n\nRunning rbac_get_user_permissions(user ops_netop) tests\n");
#endif

    tf += rbac_test_rbac_get_user_permissions(USER_GENERIC,
                             RBAC_READ_SWITCH_CONFIG, true, false);
    tf += rbac_test_rbac_get_user_permissions(USER_GENERIC,
                             RBAC_WRITE_SWITCH_CONFIG, true, false);
    tf += rbac_test_rbac_get_user_permissions(USER_GENERIC,
                             RBAC_SYS_MGMT, true, false);

    EXPECT_EQ(0,tf);
}


/*
 * Tests the rbac_get_user_permissions() interface
 * using a bogus user name
 */
TEST_F(rbac_ut,rbac_get_user_permissions_user_bogus)
{
    int tf = 0;

#ifdef SHOW_DETAIL_TESTCASES
    printf("\n\nRunning rbac_get_user_permissions(user bogus) tests\n");
#endif

    tf += rbac_test_rbac_get_user_permissions(USER_BOGUS,
                             RBAC_READ_SWITCH_CONFIG, true, false);
    tf += rbac_test_rbac_get_user_permissions(USER_BOGUS,
                             RBAC_WRITE_SWITCH_CONFIG, true, false);
    tf += rbac_test_rbac_get_user_permissions(USER_BOGUS,
                             RBAC_SYS_MGMT, true, false);

    EXPECT_EQ(0,tf);
}


/*
 * Tests the rbac_get_user_permissions() interface
 * using a blank user name
 */
TEST_F(rbac_ut,rbac_get_user_permissions_user_blank)
{
    int tf = 0;

#ifdef SHOW_DETAIL_TESTCASES
    printf("\n\nRunning rbac_get_user_permissions(user blank) tests\n");
#endif

    tf += rbac_test_rbac_get_user_permissions(USER_BLANK,
                             RBAC_READ_SWITCH_CONFIG, true, false);
    tf += rbac_test_rbac_get_user_permissions(USER_BLANK,
                             RBAC_WRITE_SWITCH_CONFIG, true, false);
    tf += rbac_test_rbac_get_user_permissions(USER_BLANK,
                             RBAC_SYS_MGMT, true, false);

    EXPECT_EQ(0,tf);
}

/*
 * Tests the rbac_get_user_permissions() interface
 * using a null user name
 */
TEST_F(rbac_ut,rbac_get_user_permissions_user_null)
{
    int tf = 0;

#ifdef SHOW_DETAIL_TESTCASES
    printf("\n\nRunning rbac_get_user_permissions(user null) tests\n");
#endif

    tf += rbac_test_rbac_get_user_permissions(USER_NULL,
                             RBAC_READ_SWITCH_CONFIG, false, false);
    tf += rbac_test_rbac_get_user_permissions(USER_NULL,
                             RBAC_WRITE_SWITCH_CONFIG, false, false);
    tf += rbac_test_rbac_get_user_permissions(USER_NULL,
                             RBAC_SYS_MGMT, false, false);

    EXPECT_EQ(0,tf);
}

/*
 * Tests the rbac_get_user_permissions() interface
 * using a created with both ops_admin and ops_netop roles.
 */
TEST_F(rbac_ut,rbac_get_user_permissions_user_multiple_roles)
{
    int tf = 0;

#ifdef SHOW_DETAIL_TESTCASES
    printf("\n\nRunning rbac_get_user_permissions(user multiple roles) tests\n");
#endif

    tf += rbac_test_rbac_get_user_permissions(USER_BOTH,
                             RBAC_READ_SWITCH_CONFIG, true, false);
    tf += rbac_test_rbac_get_user_permissions(USER_BOTH,
                             RBAC_WRITE_SWITCH_CONFIG, true, false);
    tf += rbac_test_rbac_get_user_permissions(USER_BOTH,
                             RBAC_SYS_MGMT, true, true);

    EXPECT_EQ(0,tf);
}

/*
 * Tests the rbac_get_user_permissions() interface
 * using a partial built-in user names.
 */
TEST_F(rbac_ut,rbac_get_user_permissions_partial_user_name)
{
    int tf = 0;

#ifdef SHOW_DETAIL_TESTCASES
    printf("\n\nRunning rbac_get_user_permissions(partial user name) tests\n");
#endif

    tf += rbac_test_rbac_get_user_permissions(USER_ADMIN_SHORT,
                             RBAC_READ_SWITCH_CONFIG, true, false);
    tf += rbac_test_rbac_get_user_permissions(USER_ADMIN_SHORT,
                             RBAC_WRITE_SWITCH_CONFIG, true, false);
    tf += rbac_test_rbac_get_user_permissions(USER_ADMIN_SHORT,
                             RBAC_SYS_MGMT, true, false);

    tf += rbac_test_rbac_get_user_permissions(USER_ADMIN_LONG,
                             RBAC_READ_SWITCH_CONFIG, true, false);
    tf += rbac_test_rbac_get_user_permissions(USER_ADMIN_LONG,
                             RBAC_WRITE_SWITCH_CONFIG, true, false);
    tf += rbac_test_rbac_get_user_permissions(USER_ADMIN_LONG,
                             RBAC_SYS_MGMT, true, false);

    tf += rbac_test_rbac_get_user_permissions(USER_NETOP_SHORT,
                             RBAC_READ_SWITCH_CONFIG, true, false);
    tf += rbac_test_rbac_get_user_permissions(USER_NETOP_SHORT,
                             RBAC_WRITE_SWITCH_CONFIG, true, false);
    tf += rbac_test_rbac_get_user_permissions(USER_NETOP_SHORT,
                             RBAC_SYS_MGMT, true, false);

    tf += rbac_test_rbac_get_user_permissions(USER_ADMIN_LONG,
                             RBAC_READ_SWITCH_CONFIG, true, false);
    tf += rbac_test_rbac_get_user_permissions(USER_ADMIN_LONG,
                             RBAC_WRITE_SWITCH_CONFIG, true, false);
    tf += rbac_test_rbac_get_user_permissions(USER_ADMIN_LONG,
                             RBAC_SYS_MGMT, true, false);

    EXPECT_EQ(0,tf);
}



/*
 * Main routing to start gtest code.
 */
int main(
  int    argc,
  char **argv)
{
    int r;
    printf("rbac_ut Test Harness for shared libraries");
    ::testing::InitGoogleTest(&argc, argv);
    r = RUN_ALL_TESTS();
    printf("\n\n");
    return r;
}
