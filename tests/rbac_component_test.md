#RBAC Component Test Cases
##Testcases
[TOC]
##Testcase 1: Verify root account
*Objective:* Verify if the "root" account was created properly in the system.
*Requirements:*
* Physical or Virtual Switch

*Setup:*
*Topology Diagram:

             +------------------+
             |                  |
             |  AS5712 switch   |
             |                  |
             +------------------+

*Description:*
Validate if the "root" account is created on the system.

* Steps:

1. Verify the user "root" was created on the system (DUT01).
2. Verify the "root" user started in the bash shell.
3. Verify if the user has all permissions(SYS_MGMT, READ_SWITCH_CONFIG, WRITE_SWITCH_CONFIG).

*Test result criteria*
* Test pass criteria

1. The user "root" is created on the system.
2. The "root" user starts in the bash shell.
3. The user has all permissions(SYS_MGMT, READ_SWITCH_CONFIG, WRITE_SWITCH_CONFIG).

* Test fail criteria

1. The user "root" is not created on the system.
2. The "root" user does not start in the bash shell.
3. The "root" user does not have all permissions(SYS_MGMT, READ_SWITCH_CONFIG, WRITE_SWITCH_CONFIG)

##Testcase 2: Verify admin account
*Objective:* Verify that the "admin" account was created properly in the system.
*Requirements:*
* Physical or Virtual Switch

*Setup:*
* Topology Diagram:

              +------------------+
              |                  |
              |  AS5712 switch   |
              |                  |
              +------------------+

*Description:*
Validate if the "admin" account is created on the system.

* Steps:

1. Verify the user "admin" was created on the system (DUT01)
2. Verify the "admin" user started in the bash shell
3. Verify the "admin" user has sudo privileges
4. Verify if the "admin" user is a member of the "ops_admin" group and not a member of "ovsdb-client".
5. Verify if the "admin" user has system management permissions(SYS_MGMT).
6. Verify the "admin" user does not have read and write permissions(READ_SWITCH_CONFIG, WRITE_SWITCH_CONFIG)

*Test result criteria*
* Test pass criteria

1. The user "admin" is created on the system (DUT01)
2. The "admin" user starts in the bash shell
3. The "admin" user has sudo privileges
4. The "admin" user is a member of the "ops_admin" group and not a member of "ovsdb-client".
5. The "admin" user has system management permissions(SYS_MGMT).
6. The "admin" user does not have read and write permissions(READ_SWITCH_CONFIG, WRITE_SWITCH_CONFIG)

* Test fail criteria

1. The user "admin" is not created on the system (DUT01)
2. The "admin" user does not start in the bash shell
3. The "admin" user does not have sudo privileges
4. The "admin" user is not a member of the "ops_admin" group and not a member of "ovsdb-client".
5. The "admin" user does not have system management permissions(SYS_MGMT).
6. The "admin" user has read and write permissions(READ_SWITCH_CONFIG, WRITE_SWITCH_CONFIG)

##Testcase 3: Verify netop account
*Objective:* Verify that the "netop" account was created properly in the system.
*Requirements:*
* Physical or Virtual Switch

*Setup:*
* Topology Diagram:

              +------------------+
              |                  |
              |  AS5712 switch   |
              |                  |
              +------------------+

*Description:*
* Steps:

1. Verify the user "netop" was created on the system (DUT01)
2. Verify the "netop" user started in the vtysh shell
3. Verify if the "netop" user is a member of the "ops_netop" and "ovsdb-client" groups
4. Verify if the "netop" user only has network operator permissions.(READ_SWITCH_CONFIG, WRITE_SWITCH_CONFIG)
5. Verify the "netop" user does not have sudo permissions.
6. Verify the "netop" user does not have system management permission(SYS_MGMT)

*Test result criteria*
* Test pass criteria

1. The user "netop" is created on the system (DUT01)
2. The "netop" user starts in the vtysh shell
3. The "netop" user is a member of the "ops_netop" and "ovsdb-client" groups
4. The "netop" user only has network operator permissions.(READ_SWITCH_CONFIG, WRITE_SWITCH_CONFIG)
5. The "netop" user does not have sudo permissions.
6. The "netop" user does not have system management permission(SYS_MGMT)

* Test fail criteria

1. The user "netop" is not created on the system (DUT01)
2. The "netop" user does not start in the vtysh shell
3. The "netop" user is not a member of the "ops_netop" and "ovsdb-client" groups
4. The "netop" user does not have network operator permissions.(READ_SWITCH_CONFIG, WRITE_SWITCH_CONFIG)
5. The "netop" user has sudo permissions.
6. The "netop" user has system management permission(SYS_MGMT)

##Testcase 4: Configure a new user with ops\_admin role
*Objective:* Verify if a new user can be assigned to the ops\_admin role.
*Requirements:*
* Physical or Virtual Switch

*Setup:*
* Topology Diagram:

              +------------------+
              |                  |
              |  AS5712 switch   |
              |                  |
              +------------------+

*Description:*
Validate if a new user can be assigned to the admin role.

* Steps:

1. Create a user and assign it to the ops\_admin role on the switch (DUT01)
2. Verify if the user was assigned to ops\_admin role.
3. Verify if the user started in the bash shell
4. Verify if the user has sudo privileges
5. Verify if the user has system management permissions(SYS_MGMT).
6. Verify the user does not have read and write permissions(READ_SWITCH_CONFIG, WRITE_SWITCH_CONFIG)

*Test result criteria*
* Test pass criteria

1. The user is assigned to ops\_admin role.
2. The user starts in the bash shell
3. The user has sudo privileges
4. The user has system management permissions(SYS_MGMT).
5. The user does not have read and write permissions(READ_SWITCH_CONFIG, WRITE_SWITCH_CONFIG)

* Test fail criteria

1. The user is not assigned to ops\_admin role.
2. The user does not start in the bash shell
3. The user does not have sudo privileges
4. The user does not have system management permissions(SYS_MGMT).
5. The user has read and/or write permissions(READ_SWITCH_CONFIG, WRITE_SWITCH_CONFIG)

##Testcase 5: Configure user with ops\_netop role
*Objective:* Verify if a new user can be assigned to the ops_netop role.
*Requirements:*
* Physical or Virtual Switch

*Setup:*
* Topology Diagram:

              +------------------+
              |                  |
              |  AS5712 switch   |
              |                  |
              +------------------+

*Description:*
Validate if a new user can be assigned to the netop role.

* Steps:

1. Create a user and assign it to the ops\_netop role on the switch (DUT01)
2. Verify the user started in the vtysh shell
3. Verify if the user is a member of the "ops_netop" and "ovsdb-client" groups
4. Verify if the user only has network operator permissions.(READ_SWITCH_CONFIG, WRITE_SWITCH_CONFIG)
5. Verify the user does not have sudo permissions.
6. Verify the user does not have system management permission (SYS_MGMT)

*Test result criteria*
* Test pass criteria

1. The user starts in the vtysh shell
2. The user is a member of the "ops_netop" and "ovsdb-client" groups
3. The user has network operator permissions.(READ_SWITCH_CONFIG, WRITE_SWITCH_CONFIG)
4. The user does not have sudo permissions.
5. The user does not have system management permission (SYS_MGMT)

* Test fail criteria

1. The user does not start in the vtysh shell
2. The user is not a member of the "ops_netop" and "ovsdb-client" groups
3. The user does not have network operator permissions.(READ_SWITCH_CONFIG, WRITE_SWITCH_CONFIG)
4. The user has sudo permissions.
5. The user has system management permission (SYS_MGMT)

##Testcase 6: Configure a user without a role
*Objective:* Verify if a no role user has no permissions.
*Requirements:*
* Physical or Virtual Switch

*Setup:*
* Topology Diagram:

              +------------------+
              |                  |
              |  AS5712 switch   |
              |                  |
              +------------------+

*Description:*
Validate the a user without a role does not have permissions

* Steps:

1. Create a user without a role  on the switch (DUT01)
2. Verify if the user does not belong to admin or netop role.
3. Verify if the user does not have any permission(SYS_MGMT, READ_SWITCH_CONFIG, WRITE_SWITCH_CONFIG).

*Test result criteria*
* Test pass criteria

1. The user does not belong to admin or netop role.
2. The user does not have any permission(SYS_MGMT, READ_SWITCH_CONFIG, WRITE_SWITCH_CONFIG).

* Test fail criteria

1. The user belongs to admin or netop role.
2. The user has any permission(SYS_MGMT, READ_SWITCH_CONFIG, WRITE_SWITCH_CONFIG).

##Testcase 7: Non-existent user
*Objective:* Verify if a non-existent user does not have permissions.
*Requirements:*
* Physical or Virtual Switch

*Setup:*
 * Topology Diagram:

               +------------------+
               |                  |
               |  AS5712 switch   |
               |                  |
               +------------------+

*Description:*
Validate that a non-existent user does not have permissions

* Steps:

1. Verify if the user does not have system management permissions(SYS_MGMT).
2. Verify if the user does not have network operator permissions(READ_SWITCH_CONFIG, WRITE_SWITCH_CONFIG).

*Test result criteria*
* Test pass criteria

1. The user does not have system management permissions(SYS_MGMT).
2. The user does not have network operator permissions(READ_SWITCH_CONFIG, WRITE_SWITCH_CONFIG).

* Test fail criteria

1. The user has system management permissions(SYS_MGMT).
2. The user has network operator permissions(READ_SWITCH_CONFIG, WRITE_SWITCH_CONFIG).

##Testcase 8: User assigned to two roles
*Objective:* Verify permission of a user assigned to multiple roles.
*Requirements:*
* Physical or Virtual Switch

*Setup:*
* Topology Diagram:

              +------------------+
              |                  |
              |  AS5712 switch   |
              |                  |
              +------------------+

*Description:*
Attempt to assign a new user to the netop and admin role and verify the permissions.

* Steps:

1. Create a user and assign it to the ops\_netop and ops\_admin role on the switch (DUT01)
2. Verify if the user was assigned only to ops\_admin role.
3. Verify if the user started in the bash shell
4. Verify if the user has sudo privileges
5. Verify if the user has system management permissions(SYS_MGMT).
6. Verify the user does not have read and write permissions(READ_SWITCH_CONFIG, WRITE_SWITCH_CONFIG)

*Test result criteria*
* Test pass criteria

1. The user is assigned only to ops\_admin role.
2. The user starts in the bash shell
3. The user has sudo privileges
4. The user has system management permissions(SYS_MGMT).
5. The user does not have read and write permissions(READ_SWITCH_CONFIG, WRITE_SWITCH_CONFIG)

* Test fail criteria
1. The user is not assigned only to ops\_admin role.
2. The user does not start in the bash shell
3. The user does not have sudo privileges
4. The user does not have system management permissions(SYS_MGMT).
5. The user has read and write permissions(READ_SWITCH_CONFIG, WRITE_SWITCH_CONFIG)

##Testcase 9: Verify RBAC Installation
*Objective:* Verify that the RBAC files (python and librbac.so) were installed in the appropriate locations.
*Requirements:*
* Physical or Virtual Switch

*Setup:*
* Topology Diagram:

              +------------------+
              |                  |
              |  AS5712 switch   |
              |                  |
              +------------------+

*Description:*
Validate the RBAC files were installed in appropiate locations.

* Steps:

1. Verify rbac.h was installed in the appropriate location (/usr/include).
2. Verify librbac.so was installed in the appropriate locations(/usr/lib).
3. Verify rbac.py was installed in the appropiate location (/usr/lib/python2.7/site-packages)

*Test result criteria*
* Test pass criteria

1. The rbac.h is installed in the appropriate location (/usr/include).
2. The librbac.so is installed in the appropriate locations(/usr/lib).
3. The rbac.py is installed in the appropiate location (/usr/lib/python2.7/site-packages)

* Test fail criteria

1. The rbac.h is not installed in the appropriate location (/usr/include).
2. The librbac.so is not installed in the appropriate locations(/usr/lib).
3. The rbac.py is not installed in the appropiate location (/usr/lib/python2.7/site-packages)

##Testcase 10: Range checking the RBAC interfaces
*Objective:* Verify the RBAC interfaces return the appropriate results when passed bad data.
*Requirements:*
* Physical or Virtual Switch

*Setup:*
* Topology Diagram:

              +------------------+
              |                  |
              |  AS5712 switch   |
              |                  |
              +------------------+

*Description:*
Validate the RBAC interfaces and the results when passed bad data.

* Steps:

1. Pass in a non-existent user name into the RBAC API’s
2. Pass in a null user name into the RBAC API’s where applicable
3. Pass in a null rbac_permission_t pointer into RBAC API’s where applicable
4. Pass in a null rbac_role_t pointer into RBAC API’s where applicable.

*Test result criteria*
* Test pass criteria

1. The RBAC API's does not throw an exception.
2. The RBAC API's answers the requests.

* Test fail criteria

1. The RBAC API's throws an exception.
2. The RBAC API's does not answer the requests.
