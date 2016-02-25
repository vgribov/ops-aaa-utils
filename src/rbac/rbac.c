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
#include <stdbool.h>
#include <unistd.h>
#include <grp.h>
#include <pwd.h>
#include <rbac.h>

#define ALLOW_ROOT_ROLE

/*
 * Local functions to support the public API.
 */
bool
get_rbac_role(const char *username, rbac_role_t *role)
{
   int      i;
   int      result = 0;;
   gid_t    *groups = NULL;
   int      ngroups=20;
   struct   passwd *pw;
   struct   group *g;

   if ((username == NULL) || (role == NULL))
   {
      return(false);
   }

   pw = getpwnam(username);
   if (pw == NULL)
   {
      /* No user */
      strncpy(role->name, RBAC_ROLE_NONE, sizeof (rbac_role_t));
      return(true);
   }

   role->name[0] = (char) 0;
   groups = (gid_t *) malloc (ngroups * sizeof(gid_t));
   if (groups == NULL)
   {
      return(false);
   }

   result = getgrouplist(username, pw->pw_gid, groups, &ngroups);
   if (result < 0)
   {
      free(groups);
      return(false);
   }

#ifdef ALLOW_ROOT_ROLE
   /*
    * First check for root role.
    */
   for (i = 0; i < ngroups; i++)
   {
      g = getgrgid(groups[i]);
      if (strncmp(g->gr_name, RBAC_ROLE_ROOT, RBAC_MAX_ROLE_NAME_LEN) == 0)
      {
         strncpy(role->name, RBAC_ROLE_ROOT, sizeof (rbac_role_t));
         free(groups);
         return(true);
      }
   }
#endif

   /*
    * Next check for admin role.
    */
   for (i = 0; i < ngroups; i++)
   {
      g = getgrgid(groups[i]);
      if (strncmp(g->gr_name, RBAC_ROLE_ADMIN, RBAC_MAX_ROLE_NAME_LEN) == 0)
      {
         strncpy(role->name, RBAC_ROLE_ADMIN, sizeof (rbac_role_t));
         free(groups);
         return(true);
      }
   }

   /*
    * Finally check for netop role.
    */
   for (i = 0; i < ngroups; i++)
   {
      g = getgrgid(groups[i]);
      if (strncmp(g->gr_name, RBAC_ROLE_NETOP, RBAC_MAX_ROLE_NAME_LEN) == 0)
      {
         strncpy(role->name, RBAC_ROLE_NETOP, sizeof (rbac_role_t));
         free(groups);
         return(true);
      }
   }

   strncpy(role->name, RBAC_ROLE_NONE, RBAC_MAX_ROLE_NAME_LEN);
   free(groups);
   return(true);
}

bool
get_rbac_permissions(const char *username, rbac_permissions_t *permissions)
{
   bool          result;
   rbac_role_t   role;

   if ((username == NULL) || (permissions == NULL))
   {
       return(false);
   }

   /*
    * Get the user's role.
    */
   permissions->count = 0;
   result =  get_rbac_role(username, &role);
   if (result == false)
   {
      return(false);
   }

#ifdef ALLOW_ROOT_ROLE
   if (strncmp(role.name, RBAC_ROLE_ROOT, RBAC_MAX_ROLE_NAME_LEN) == 0)
   {
      permissions->count = 3;
      strcpy(permissions->name[0], RBAC_SYS_MGMT);
      strcpy(permissions->name[1], RBAC_READ_SWITCH_CONFIG);
      strcpy(permissions->name[2], RBAC_WRITE_SWITCH_CONFIG);
      return(true);
   }
#endif

   if (strncmp(role.name, RBAC_ROLE_ADMIN, RBAC_MAX_ROLE_NAME_LEN) == 0)
   {
      permissions->count = 1;
      strcpy(permissions->name[0], RBAC_SYS_MGMT);
      return(true);
   }

   if (strncmp(role.name, RBAC_ROLE_NETOP, RBAC_MAX_ROLE_NAME_LEN) == 0)
   {
      permissions->count = 2;
      strcpy(permissions->name[0], RBAC_READ_SWITCH_CONFIG);
      strcpy(permissions->name[1], RBAC_WRITE_SWITCH_CONFIG);
      return(true);
   }

   permissions->count = 0;
   return(true);

}

/*
 * externally callable functions
 */

/*
 * Check if user has rights to a permission
 *
 * Returns true the specified user has rights to this permission,
 * otherwise returns false.
 */
bool
rbac_check_user_permission(const char *username, const char *permission)
{
    rbac_permissions_t     permissions;
    bool                   result;
    int                    i;

    if ((username == NULL) || (permission == NULL))
    {
       return(false);
    }

   result = get_rbac_permissions(username, &permissions);
   if (result == false)
   {
      return(false);
   }

   for (i = 0; i < permissions.count; i++)
   {
       if (strncmp(permissions.name[i], permission,
                            RBAC_MAX_PERMISSION_NAME_LEN) == 0)
       {
       return(true);
       }
   }
   return(false);
}

/*
 * Returns the users list of permissions.
 *
 * Returns true if if rbac_permissions_t structure contains the
 * users permissions, otherwise returns false.
 */
bool
rbac_get_user_permissions(const char *username, rbac_permissions_t *permissions)
{
    bool   result;
    if ((username == NULL) || (permissions == NULL))
    {
       return(false);
    }

   result = get_rbac_permissions(username, permissions);
   return(result);
}

/*
 * Returns the role of the specified user.
 *
 * Returns true if if rbac_role_t structure contains the
 * role string, otherwise returns false.
 */
bool
rbac_get_user_role(const char *username, rbac_role_t *role)
{
    bool     result;

    if ((username == NULL) || (role == NULL))
    {
       return(false);
    }
    result = get_rbac_role(username, role);
    return(result);
}
