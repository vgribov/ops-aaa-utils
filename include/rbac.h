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
 * File: rbac.h
 *
 * Purpose: To add declarations required for call the RBAC API's
 *
 */
#ifndef RBAC_H
#define RBAC_H
#include <stdbool.h>

#define RBAC_MAX_NUM_PERMISSIONS                5
#define RBAC_MAX_PERMISSION_NAME_LEN            25
#define RBAC_MAX_ROLE_NAME_LEN                  20

#define RBAC_ROLE_ROOT                          "root"
#define RBAC_ROLE_ADMIN                         "ops_admin"
#define RBAC_ROLE_NETOP                         "ops_netop"
#define RBAC_ROLE_NONE                          "none"

#define RBAC_READ_SWITCH_CONFIG                 "READ_SWITCH_CONFIG"
#define RBAC_WRITE_SWITCH_CONFIG                "WRITE_SWITCH_CONFIG"
#define RBAC_SYS_MGMT                           "SYS_MGMT"

typedef struct {
  char name[RBAC_MAX_ROLE_NAME_LEN];
} rbac_role_t;

typedef struct {
  int count;
  char name[RBAC_MAX_NUM_PERMISSIONS][RBAC_MAX_PERMISSION_NAME_LEN];
} rbac_permissions_t;

#ifdef __cplusplus
extern "C" {
#endif
extern bool rbac_check_user_permission(const char *username, const char *permissions);
extern bool rbac_get_user_permissions(const char *username, rbac_permissions_t *permissions);
extern bool rbac_get_user_role(const char *username, rbac_role_t *role);
#ifdef __cplusplus
}
#endif

#endif /* RBAC_H */
