/* AAA deamon client callback registration source files.
 *
 * Copyright (C) 2016 Hewlett Packard Enterprise Development LP.
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2, or (at your option) any
 * later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 *
 * File: vtysh_ovsdb_aaa_context.c
 *
 * Purpose: Source for registering sub-context callback with
 *          global config context.
 */

#include "vtysh/vty.h"
#include "vtysh/vector.h"
#include "vswitch-idl.h"
#include "openswitch-idl.h"
#include "vtysh/vtysh_ovsdb_if.h"
#include "vtysh/vtysh_ovsdb_config.h"
#include "vtysh/utils/system_vtysh_utils.h"
#include "vtysh_ovsdb_aaa_context.h"
#include "aaa_vty.h"

/*-----------------------------------------------------------------------------
| Function : vtysh_ovsdb_ovstable_parse_tacacs_cfg
| Responsibility : parse tacacs config in aaa column in system table
| Parameters :
|    ifrow_aaa : aaa column object pointer
|    pmsg : callback arguments from show running config handler|
-----------------------------------------------------------------------------*/
static vtysh_ret_val
vtysh_ovsdb_ovstable_parse_tacacs_cfg(const struct smap *ifrow_aaa, vtysh_ovsdb_cbmsg *p_msg)
{
  const char *timeout = NULL;
  const char *passkey = NULL;
  const char *auth_type = NULL;

  if(ifrow_aaa == NULL)
  {
    return e_vtysh_error;
  }

  passkey = smap_get(ifrow_aaa, SYSTEM_AAA_TACACS_PASSKEY);
  if (passkey)
  {
    if (!VTYSH_STR_EQ(passkey, TACACS_SERVER_PASSKEY_DEFAULT))
    {
        vtysh_ovsdb_cli_print(p_msg, "tacacs-server key %s", passkey);
    }
  }

  timeout = smap_get(ifrow_aaa, SYSTEM_AAA_TACACS_TIMEOUT);
  if (timeout)
  {
    if (!VTYSH_STR_EQ(timeout, TACACS_SERVER_TIMEOUT_DEFAULT_VAL))
    {
        vtysh_ovsdb_cli_print(p_msg, "tacacs-server timeout %s", timeout);
    }
  }

  auth_type = smap_get(ifrow_aaa, SYSTEM_AAA_TACACS_AUTH);
  if (auth_type)
  {
    if (!VTYSH_STR_EQ(auth_type, TACACS_SERVER_AUTH_TYPE_DEFAULT))
    {
        vtysh_ovsdb_cli_print(p_msg, "tacacs-server auth-type %s", auth_type);
    }
  }

  return e_vtysh_ok;
}

/* Utility functions for tacacs server display*/

/* qsort comparator function: default_priority*/
int
compare_nodes_by_tacacs_server_default_priority (const void *a, const void *b)
{
    const struct shash_node *const *node_a = a;
    const struct shash_node *const *node_b = b;
    const struct ovsrec_tacacs_server *server_a =
                      (const struct ovsrec_tacacs_server *)(*node_a)->data;
    const struct ovsrec_tacacs_server *server_b =
                      (const struct ovsrec_tacacs_server *)(*node_b)->data;

    return (server_a->default_priority - server_b->default_priority);
}


/* qsort comparator function: group_priority*/
int
compare_nodes_by_tacacs_server_group_priority (const void *a, const void *b)
{
    const struct shash_node *const *node_a = a;
    const struct shash_node *const *node_b = b;
    const struct ovsrec_tacacs_server *server_a =
                      (const struct ovsrec_tacacs_server *)(*node_a)->data;
    const struct ovsrec_tacacs_server *server_b =
                      (const struct ovsrec_tacacs_server *)(*node_b)->data;

    return (server_a->group_priority - server_b->group_priority);
}

/*
 * Sorting function for tacacs servers
 * on success, returns sorted tacacs server list.
 */
const struct shash_node **
sort_tacacs_server(const struct shash *list, bool by_default_priority)
{
    if (shash_is_empty(list))
    {
        return NULL;
    }
    else
    {
        const struct shash_node **nodes;
        struct shash_node *node;
        size_t iter = 0;
        size_t count = 0;

        count = shash_count(list);
        nodes = malloc(count * sizeof(*nodes));
        if (nodes == NULL)
          return NULL;
        SHASH_FOR_EACH (node, list) {
            nodes[iter++] = node;
        }
        if (by_default_priority)
            qsort(nodes, count, sizeof(*nodes), compare_nodes_by_tacacs_server_default_priority);
        else
            qsort(nodes, count, sizeof(*nodes), compare_nodes_by_tacacs_server_group_priority);
        return nodes;
    }
}

/*-----------------------------------------------------------------------------
| Function : vtysh_display_tacacs_server_table
| Responsibility : display tacacs server table
| scope : static
| Parameters :
|    pmsg : callback arguments from show running config handler|
| Return : vtysh_ret_val, e_vtysh_ok
-----------------------------------------------------------------------------*/
static vtysh_ret_val
vtysh_display_tacacs_server_table(vtysh_ovsdb_cbmsg *p_msg)
{
  const struct ovsrec_tacacs_server *row = NULL;
  struct shash sorted_tacacs_servers;
  const struct shash_node **nodes;
  int count = 0;
  int idx = 0;
  bool sort_by_default_priority = true;

  if (!ovsrec_tacacs_server_first(p_msg->idl))
  {
      return e_vtysh_ok;
  }

  shash_init(&sorted_tacacs_servers);

  OVSREC_TACACS_SERVER_FOR_EACH(row, p_msg->idl)
  {
      shash_add(&sorted_tacacs_servers, row->ip_address, (void *)row);
  }

  nodes = sort_tacacs_server(&sorted_tacacs_servers, sort_by_default_priority);
  if (nodes == NULL)
  {
     shash_destroy(&sorted_tacacs_servers);
     return e_vtysh_error;
  }
  count = shash_count(&sorted_tacacs_servers);

  vtysh_ovsdb_cli_print(p_msg, "!");
  for(idx = 0; idx < count; idx++)
  {
      /*
       * buff size based on port 11 " port %5d", timeout 11 " timeout %2d"
       * key 63 " key %58s"  auth_type 15 " auth-type %4s"
       */
      char buff[128]= {0};
      char *append_buff = buff;
      row = (const struct ovsrec_tacacs_server *)nodes[idx]->data;

      if (row->tcp_port && row->tcp_port != TACACS_SERVER_TCP_PORT_DEFAULT)
         append_buff += sprintf(append_buff, " port %ld", row->tcp_port);

      if (row->timeout)
         append_buff += sprintf(append_buff, " timeout %ld", *(row->timeout));

      if (row->passkey)
         append_buff += sprintf(append_buff, " key %s", row->passkey);

      if (row->auth_type)
         append_buff += sprintf(append_buff, " auth-type %s", row->auth_type);

      vtysh_ovsdb_cli_print(p_msg, "tacacs-server host %s%s",
                                    row->ip_address, buff);
  }

  shash_destroy(&sorted_tacacs_servers);
  free(nodes);

  return e_vtysh_ok;
}


/*-----------------------------------------------------------------------------
| Function : vtysh_display_aaa_server_group_priority_authentication
| Responsibility : display tacacs server group_priority for tacacs authentication
| scope : static
| Parameters :
|    pmsg : callback arguments from show running config handler|
| Return : vtysh_ret_val, e_vtysh_ok
-----------------------------------------------------------------------------*/
static vtysh_ret_val
vtysh_display_aaa_server_group_priority_authentication(vtysh_ovsdb_cbmsg *p_msg)
{
  int count = 0;
  const struct ovsrec_aaa_server_group *group_row = NULL;
  const struct ovsrec_aaa_server_group_prio *group_prio_list = NULL;

  group_prio_list = ovsrec_aaa_server_group_prio_first(p_msg->idl);

  if (!group_prio_list)
  {
      return e_vtysh_ok;
  }

  count = group_prio_list->n_authentication_group_prios;

  if (count > 1)
  {
     char buff[1024]= {0};
     char *append_buff = buff;
     int iter = 0;
     for(iter = 0; iter < count; iter ++)
     {
         group_row = group_prio_list->value_authentication_group_prios[iter];

         append_buff += sprintf(append_buff, " %s", group_row->group_name);
     }

     vtysh_ovsdb_cli_print(p_msg, "aaa authentication login default group%s", buff);
  }

  else
  {
     group_row = group_prio_list->value_authentication_group_prios[0];
     if (!VTYSH_STR_EQ(group_row->group_name,SYSTEM_AAA_LOCAL))
     {
         vtysh_ovsdb_cli_print(p_msg, "aaa authentication login default group %s", group_row->group_name);
     }
     else if(group_prio_list->key_authentication_group_prios[0] != 0)
     {
         vtysh_ovsdb_cli_print(p_msg, "aaa authentication login default local");
     }
  }

  return e_vtysh_ok;
}

/*-----------------------------------------------------------------------------
| Function : vtysh_display_aaa_fail_through_status
| Responsibility : display AAA fail-through status
| scope : static
| Parameters :
|    ifrow_aaa : aaa column object pointer
|    pmsg : callback arguments from show running config handler
| Return : e_vtysh_error, e_vtysh_ok
-----------------------------------------------------------------------------*/
static vtysh_ret_val
vtysh_display_aaa_fail_through_status(const struct smap *ifrow_aaa, vtysh_ovsdb_cbmsg *p_msg)
{
  const char *fail_through = NULL;

  if(ifrow_aaa == NULL)
  {
    return e_vtysh_error;
  }

  fail_through = smap_get(ifrow_aaa, SYSTEM_AAA_FAIL_THROUGH);
  if (fail_through)
  {
    if (!VTYSH_STR_EQ(fail_through, SYSTEM_AAA_FAIL_THROUGH_DEFAULT))
    {
        vtysh_ovsdb_cli_print(p_msg, "aaa authentication allow-fail-through");
    }
  }

  return e_vtysh_ok;
}


/*-----------------------------------------------------------------------------
| Function : vtysh_display_aaa_server_group_priority_authorization
| Responsibility : display tacacs server group_priority for tacacs authorization
| scope : static
| Parameters :
|    pmsg : callback arguments from show running config handler|
| Return : vtysh_ret_val, e_vtysh_ok
-----------------------------------------------------------------------------*/
static vtysh_ret_val
vtysh_display_aaa_server_group_priority_authorization(vtysh_ovsdb_cbmsg *p_msg)
{
  int count = 0;
  const struct ovsrec_aaa_server_group *group_row = NULL;
  const struct ovsrec_aaa_server_group_prio *group_prio_list = NULL;

  group_prio_list = ovsrec_aaa_server_group_prio_first(p_msg->idl);

  count = group_prio_list->n_authorization_group_prios;

  if (count > 1)
  {
     char buff[BUFSIZE]= {0};
     char *append_buff = buff;
     int offset = 0;
     int iter = 0;
     for(iter = 0; iter < count; iter ++)
     {
         group_row = group_prio_list->value_authorization_group_prios[iter];

         offset += snprintf(append_buff + offset, BUFSIZE - offset, " %s", group_row->group_name);
     }

     vtysh_ovsdb_cli_print(p_msg, "aaa authorization commands default group%s", buff);
  }
  else
  {
     group_row = group_prio_list->value_authorization_group_prios[0];
     if (!VTYSH_STR_EQ(group_row->group_name,SYSTEM_AAA_NONE))
     {
         vtysh_ovsdb_cli_print(p_msg, "aaa authorization commands default group %s", group_row->group_name);
     }
     else if(group_prio_list->key_authorization_group_prios[0] != 0)
     {
         vtysh_ovsdb_cli_print(p_msg, "aaa authorization commands default none");
     }
  }

  return e_vtysh_ok;
}

/*-----------------------------------------------------------------------------
| Function : vtysh_display_aaa_server_group_table
| Responsibility : display AAA Server Group table
| scope : static
| Parameters :
|    pmsg : callback arguments from show running config handler|
| Return : vtysh_ret_val, e_vtysh_ok
-----------------------------------------------------------------------------*/
static vtysh_ret_val
vtysh_display_aaa_server_group_table(vtysh_ovsdb_cbmsg *p_msg)
{
  const struct ovsrec_tacacs_server *server_row = NULL;
  const struct ovsrec_aaa_server_group *group_row = NULL;
  struct shash sorted_tacacs_servers;
  const struct shash_node **nodes;
  int count = 0;
  int idx = 0;
  bool by_default_priority = false;

  if (!ovsrec_aaa_server_group_first(p_msg->idl))
  {
      return e_vtysh_ok;
  }

  shash_init(&sorted_tacacs_servers);

  OVSREC_TACACS_SERVER_FOR_EACH(server_row, p_msg->idl)
  {
      shash_add(&sorted_tacacs_servers, server_row->ip_address, (void *)server_row);
  }

  nodes = sort_tacacs_server(&sorted_tacacs_servers, by_default_priority);
  count = shash_count(&sorted_tacacs_servers);

  OVSREC_AAA_SERVER_GROUP_FOR_EACH(group_row, p_msg->idl)
  {
      const char* name = group_row->group_name;
      if ((strcmp(name, SYSTEM_AAA_LOCAL) == 0) ||
          (strcmp(name, SYSTEM_AAA_NONE) == 0) ||
          (strcmp(name, SYSTEM_AAA_RADIUS) == 0) ||
          (strcmp(name, SYSTEM_AAA_TACACS_PLUS) == 0))
      {
          continue;
      }
      vtysh_ovsdb_cli_print(p_msg, "!");
      vtysh_ovsdb_cli_print(p_msg, "aaa group server tacacs+ %s", name);

      for(idx = 0; idx < count; idx++)
      {
          server_row = (const struct ovsrec_tacacs_server *)nodes[idx]->data;
          if (server_row->group == group_row)
          {
              if (server_row->tcp_port != TACACS_SERVER_TCP_PORT_DEFAULT)
              {
                  vtysh_ovsdb_cli_print(p_msg, "    server %s port %ld",
                                        server_row->ip_address, server_row->tcp_port);
              }
              else
              {
                  vtysh_ovsdb_cli_print(p_msg, "    server %s", server_row->ip_address);
              }
          }
      }
  }

  shash_destroy(&sorted_tacacs_servers);
  free(nodes);

  return e_vtysh_ok;
}

/*-----------------------------------------------------------------------------
| Function : vtysh_config_context_aaa_clientcallback
| Responsibility : AAA config client callback routine
| Parameters :
|     void *p_private: void type object typecast to required
| Return : error/ok
-----------------------------------------------------------------------------*/
vtysh_ret_val
vtysh_config_context_aaa_clientcallback(void *p_private)
{
    vtysh_ovsdb_cbmsg_ptr p_msg = (vtysh_ovsdb_cbmsg *)p_private;
    const struct ovsrec_system *vswrow;
    vtysh_ovsdb_config_logmsg(VTYSH_OVSDB_CONFIG_DBG,
                              "vtysh_config_context_aaa_clientcallback entered");
    vswrow = ovsrec_system_first(p_msg->idl);

    if(vswrow)
    {
       /* Generate CLI for aaa column */
       vtysh_ovsdb_ovstable_parse_tacacs_cfg(&vswrow->aaa, p_msg);
    }

    /* Generate CLI for the Tacacs_Server Table*/
    vtysh_display_tacacs_server_table(p_msg);

    if (vswrow)
    {
        /* Generate CLI for fail-through */
        vtysh_display_aaa_fail_through_status(&vswrow->aaa, p_msg);
    }

    /* Generate CLI for the AAA_Server_Group Table*/
    vtysh_display_aaa_server_group_table(p_msg);
    /* Generate CLI for the AAA_Server_Group_Prio Table for authentication*/
    vtysh_display_aaa_server_group_priority_authentication(p_msg);
    /* Generate CLI for the AAA_Server_Group_Prio Table for authorization*/
    vtysh_display_aaa_server_group_priority_authorization(p_msg);


    return e_vtysh_ok;
}
