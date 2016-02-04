/*
 * Copyright (C) 2016 Hewlett Packard Enterprise Development LP
 * All Rights Reserved.
 *
 *   Licensed under the Apache License, Version 2.0 (the "License"); you may
 *   not use this file except in compliance with the License. You may obtain
 *   a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *   License for the specific language governing permissions and limitations
 *   under the License.
 *
 * File: rbac.c
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <grp.h>
#include <rbac.h>

/*
 * Returns true if a user has access rights to the permission.
 */
bool
rbac_check_user_permission(const char *username, const char *permission)
{

    if ((username == NULL) || (permission == NULL)) {
       return(false);
    }

   if ((strncmp(permission, RBAC_READ_SWITCH_CONFIG,
                RBAC_MAX_PERMISSION_NAME_LEN) == 0) ||
       (strncmp(permission, RBAC_WRITE_SWITCH_CONFIG,
               RBAC_MAX_PERMISSION_NAME_LEN) == 0)) {
       return(true);
       }
   return(false);

}

/*
 * Returns an array of permissions a user has access rights to.
 */
bool
rbac_get_user_permissions(const char *username,
                          rbac_permissions_t *permissions)
{
    if ((username == NULL) || (permissions == NULL)) {
       return(false);
    }

    permissions->count = 2;
    strcpy(permissions->name[0], RBAC_READ_SWITCH_CONFIG);
    strcpy(permissions->name[1], RBAC_WRITE_SWITCH_CONFIG);
    return(true);
}

/*
 * Returns the role of the user.
 */
bool
rbac_get_user_role(const char *username, rbac_role_t *role)
{
    if ((username == NULL) || (role == NULL)) {
       return(false);
    }
    strcpy(role->name, RBAC_ROLE_NETOP);
    return(true);
}
