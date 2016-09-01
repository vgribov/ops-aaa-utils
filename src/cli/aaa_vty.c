/* AAA CLI commands.
 *
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
 * Copyright (C) 2015-2016 Hewlett Packard Enterprise Development LP
 *
 * This Program is free software; you can redistribute it and/or modify it
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
 * along with this program; see the file COPYING.  If not, write to the Free
 * Software Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 *
 * File: aaa_vty.c
 *
 * Purpose:  To add AAA CLI configuration and display commands.
 */

#include <sys/un.h>
#include <setjmp.h>
#include <sys/wait.h>
#include <pwd.h>

#include <readline/readline.h>
#include <readline/history.h>

#include <lib/version.h>
#include "getopt.h"
#include "vtysh/command.h"
#include "vtysh/memory.h"
#include "vtysh/vtysh.h"
#include "vtysh/vtysh_user.h"
#include "vswitch-idl.h"
#include "ovsdb-idl.h"
#include "aaa_vty.h"
#include "smap.h"
#include "openvswitch/vlog.h"
#include "openswitch-idl.h"
#include "vtysh/vtysh_ovsdb_if.h"
#include "vtysh/vtysh_ovsdb_config.h"
#include "vtysh/utils/ovsdb_vtysh_utils.h"
#include "vtysh_ovsdb_aaa_context.h"
#include <arpa/inet.h>
#include <string.h>

extern struct ovsdb_idl *idl;

static int aaa_set_global_status (const char *status, bool no_flag);
static int aaa_set_radius_authentication(const char *auth);
static int aaa_fallback_option (const char *value);
static int aaa_show_aaa_authenctication ();
static int tacacs_set_global_passkey (const char *passkey);
static int tacacs_set_global_port (const char *port);
static int tacacs_set_global_timeout (const char *timeout);
static const struct ovsrec_aaa_server_group*
           get_row_by_server_group_name(const char *name);
static const struct ovsrec_tacacs_server*
           get_tacacs_server_by_name_port(const char *server_name, int64_t auth_port);
static int show_aaa_authentication_priority_group();
static int radius_server_add_host (const char *ipv4);
static int radius_server_remove_auth_port (const char *ipv4,
                       const char *authport);
static int radius_server_remove_passkey (const char *ipv4,
                     const char *passkey);
static int radius_server_remove_host (const char *ipv4);
static int radius_server_passkey_host (const char *ipv4, const char *passkey);
static int radius_server_set_retries (const char *retries);
static int radius_server_remove_retries (const char *retries_t);
static int radius_server_set_timeout (const char *timeout);
static int radius_server_remove_timeout (const char *timeout_t);
static int radius_server_set_auth_port (const char *ipv4, const char *port);
static int show_radius_server_info ();
static int show_auto_provisioning ();
static int show_ssh_auth_method ();
static int set_ssh_publickey_auth (const char *status);
static int set_ssh_password_auth (const char *status);

VLOG_DEFINE_THIS_MODULE(vtysh_aaa_cli);

/* Set global status of AAA. */
static int
aaa_set_global_status(const char *status, bool no_flag)
{
    const struct ovsrec_system *row = NULL;
    enum ovsdb_idl_txn_status txn_status;
    struct ovsdb_idl_txn *status_txn = cli_do_config_start();
    struct smap smap_aaa;

    if (status_txn == NULL)
    {
        VLOG_ERR(OVSDB_TXN_CREATE_ERROR);
        cli_do_config_abort(status_txn);
        return CMD_OVSDB_FAILURE;
    }

    row = ovsrec_system_first(idl);

    if (!row)
    {
        VLOG_ERR(OVSDB_ROW_FETCH_ERROR);
        cli_do_config_abort(status_txn);
        return CMD_OVSDB_FAILURE;
    }

    smap_clone(&smap_aaa, &row->aaa);

    /* handle no command: reset aaa authentication to local */
    if (no_flag)
    {
        smap_replace(&smap_aaa, SYSTEM_AAA_RADIUS, OPS_FALSE_STR);
        smap_replace(&smap_aaa, SYSTEM_AAA_RADIUS_AUTH, RADIUS_PAP);
    }
    else
    {
        if (strcmp(SYSTEM_AAA_RADIUS, status) == 0)
        {
            smap_replace(&smap_aaa, SYSTEM_AAA_RADIUS, OPS_TRUE_STR);
            smap_replace(&smap_aaa, SYSTEM_AAA_RADIUS_AUTH, RADIUS_PAP);
        }
        else if (strcmp(SYSTEM_AAA_RADIUS_LOCAL, status) == 0)
        {
            smap_replace(&smap_aaa, SYSTEM_AAA_RADIUS, OPS_FALSE_STR);
            smap_replace(&smap_aaa, SYSTEM_AAA_RADIUS_AUTH, RADIUS_PAP);
        }
    }

    ovsrec_system_set_aaa(row, &smap_aaa);
    smap_destroy(&smap_aaa);

    txn_status = cli_do_config_finish(status_txn);

    if (txn_status == TXN_SUCCESS || txn_status == TXN_UNCHANGED)
    {
        return CMD_SUCCESS;
    }
    else
    {
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }
}

/* CLI to configure either local or radius configuration. */
DEFUN(cli_aaa_set_global_status,
        aaa_set_global_status_cmd,
        "aaa authentication login (radius | local)",
        AAA_STR
        "User authentication\n"
        "Switch login\n" "Radius authentication\n \
         Local authentication (Default)\n")
{
    bool is_no_cmd = false;

    if (vty_flags & CMD_FLAG_NO_CMD) {
        is_no_cmd = true;
    }

    return aaa_set_global_status(argv[0], is_no_cmd);
}

DEFUN_NO_FORM(cli_aaa_set_global_status,
              aaa_set_global_status_cmd,
              "aaa authentication login",
              AAA_STR
              "User authentication\n"
              "Switch login\n");

/* AAA server group utility functions*/
static const struct ovsrec_aaa_server_group*
get_row_by_server_group_name(const char *name)
{
    const struct ovsrec_aaa_server_group *row = NULL;
    OVSREC_AAA_SERVER_GROUP_FOR_EACH(row, idl) {
        if (strcmp(row->group_name, name) == 0)
        {
            return row;
        }
    }
    return NULL;
}

const bool
server_group_exists(const char *name)
{
    return get_row_by_server_group_name(name) != NULL;
}

const int
configure_aaa_server_group_priority(aaa_server_group_prio_params_t *group_prio_params)
{
    struct ovsdb_idl_txn *priority_txn = NULL;
    const struct ovsrec_aaa_server_group *group_row = NULL;
    const struct ovsrec_aaa_server_group_prio *group_prio_default = NULL;
    int64_t priority = 0;
    int iter = 0;
    int64_t *key_list = NULL;
    struct ovsrec_aaa_server_group **value_list = NULL;
    int64_t group_count = group_prio_params->group_count;
    /* Start of transaction */
    START_DB_TXN(priority_txn);

    /* TODO rework code when add login type support for : console, ssh and telnet*/
    group_prio_default = ovsrec_aaa_server_group_prio_first(idl);

    if (group_prio_default == NULL)
    {
        ERRONEOUS_DB_TXN(priority_txn, "Could not access 'default' entry of AAA_Server_Group_Prio Table");
    }

    /* Reset local group priority to 0 for no version of command */
    if (group_prio_params->no_form)
    {
        key_list = xmalloc(sizeof(int64_t));
        group_row = get_row_by_server_group_name(SYSTEM_AAA_LOCAL);
        if (group_row == NULL)
        {
                ERRONEOUS_DB_TXN(priority_txn, "AAA server group does not exist.");
        }
        value_list = xmalloc(sizeof(*group_row));
        key_list[0] = priority;
        value_list[0] = (struct ovsrec_aaa_server_group *)group_row;
        group_count = 1;
    }

    else
    {
        priority = 1;
        key_list = xmalloc(sizeof(int64_t) * group_count);
        value_list = xmalloc(sizeof(*group_row) * group_count);
        for (iter = 0; iter < group_count; iter++)
        {
            group_row = get_row_by_server_group_name(group_prio_params->group_list[iter]);
            if (group_row == NULL) {
                ERRONEOUS_DB_TXN(priority_txn, "AAA server group does not exist.");
            }
            key_list[iter] = priority;
            value_list[iter] = (struct ovsrec_aaa_server_group *)group_row;
            priority ++;
        }
    }

    ovsrec_aaa_server_group_prio_set_authentication_group_prios(group_prio_default,
                                                                key_list, value_list,
                                                                group_count);
    free(key_list);
    free(value_list);
    /* End of transaction. */
    END_DB_TXN(priority_txn);
}

DEFUN(cli_aaa_set_authentication,
      aaa_set_authentication_cmd,
      "aaa authentication login default {local | group .WORD}",
      AAA_STR
      AAA_AUTHENTICATION_HELP_STR
      AAA_LOGIN_HELP_STR
      AAA_DEFAULT_LINE_HELP_STR
      AAA_LOCAL_AUTHENTICATION_HELP_STR
      GROUP_HELP_STR
      GROUP_NAME_HELP_STR)

{
    char **group_list = NULL;
    int group_count = 0;
    int keyword_skip = 0;
    aaa_server_group_prio_params_t group_prio_params;

    if (argc >= 1)
    {
        if ( !argv[0] || VTYSH_STR_EQ(argv[0], AAA_GROUP))
        {
           keyword_skip = 1;
           group_count = argc - keyword_skip;
        }
        else if (VTYSH_STR_EQ(argv[0], SYSTEM_AAA_LOCAL))
        {
           group_count = 1;
        }
        group_list = xmalloc(sizeof(char *) * group_count);
        memcpy(group_list, argv + keyword_skip, sizeof(char *) * group_count);
    }

    group_prio_params.no_form = false;
    group_prio_params.group_count = group_count;
    group_prio_params.group_list = group_list;
    group_prio_params.aaa_method = authentication;
    group_prio_params.login_type = AAA_SERVER_GROUP_PRIO_SESSION_TYPE_DEFAULT;

    if (vty_flags & CMD_FLAG_NO_CMD)
    {
        group_prio_params.no_form = true;
    }

    return configure_aaa_server_group_priority(&group_prio_params);
}

DEFUN_NO_FORM(cli_aaa_set_authentication,
              aaa_set_authentication_cmd,
              "aaa authentication login default",
              AAA_STR
              AAA_AUTHENTICATION_HELP_STR
              AAA_LOGIN_HELP_STR
              AAA_DEFAULT_LINE_HELP_STR);

/* Set AAA radius authentication encoding to CHAP or PAP
 * On success, returns CMD_SUCCESS. On failure, returns CMD_OVSDB_FAILURE.
 */
static int aaa_set_radius_authentication(const char *auth)
{
    const struct ovsrec_system *row = NULL;
    enum ovsdb_idl_txn_status txn_status;
    struct ovsdb_idl_txn *status_txn = cli_do_config_start();
    struct smap smap_aaa;

    if (status_txn == NULL)
    {
        VLOG_ERR(OVSDB_TXN_CREATE_ERROR);
        cli_do_config_abort(status_txn);
        return CMD_OVSDB_FAILURE;
    }

    row = ovsrec_system_first(idl);

    if (!row)
    {
        VLOG_ERR(OVSDB_ROW_FETCH_ERROR);
        cli_do_config_abort(status_txn);
        return CMD_OVSDB_FAILURE;
    }

    smap_clone(&smap_aaa, &row->aaa);

    if (strcmp(RADIUS_CHAP, auth) == 0)
    {
        smap_replace(&smap_aaa, SYSTEM_AAA_RADIUS, OPS_TRUE_STR);
        smap_replace(&smap_aaa, SYSTEM_AAA_RADIUS_AUTH, RADIUS_CHAP);
    }
    else if (strcmp(RADIUS_PAP, auth) == 0)
    {
        smap_replace(&smap_aaa, SYSTEM_AAA_RADIUS, OPS_TRUE_STR);
        smap_replace(&smap_aaa, SYSTEM_AAA_RADIUS_AUTH, RADIUS_PAP);
    }

    ovsrec_system_set_aaa(row, &smap_aaa);
    smap_destroy(&smap_aaa);

    txn_status = cli_do_config_finish(status_txn);

    if (txn_status == TXN_SUCCESS || txn_status == TXN_UNCHANGED)
    {
        return CMD_SUCCESS;
    }
    else
    {
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }
}

/* CLI to set AAA radius authentication encoding to PAP or CHAP. */
DEFUN (cli_aaa_set_radius_authentication,
         aaa_set_radius_authentication_cmd,
         "aaa authentication login radius radius-auth ( pap | chap)",
         AAA_STR
         "User authentication\n"
         "Switch login\n"
         "Radius authentication\n"
         "Radius authentication type\n"
         "Set PAP Radius authentication\n"
         "Set CHAP Radius authentication\n")
{
    return aaa_set_radius_authentication(argv[0]);
}

/* Set AAA fallback options to either True or False.
 * On success, returns CMD_SUCCESS. On failure, returns CMD_OVSDB_FAILURE.
 */
static int
aaa_fallback_option(const char *value)
{
    const struct ovsrec_system *row = NULL;
    enum ovsdb_idl_txn_status txn_status;
    struct ovsdb_idl_txn *status_txn = cli_do_config_start();
    struct smap smap_aaa;

    if (status_txn == NULL)
    {
        VLOG_ERR(OVSDB_TXN_CREATE_ERROR);
        cli_do_config_abort(status_txn);
        return CMD_OVSDB_FAILURE;
    }

    row = ovsrec_system_first(idl);

    if (!row)
    {
        VLOG_ERR(OVSDB_ROW_FETCH_ERROR);
        cli_do_config_abort(status_txn);
        return CMD_OVSDB_FAILURE;
    }

    smap_clone(&smap_aaa, &row->aaa);

    if ((strcmp(value, OPS_TRUE_STR) == 0))
    {
        smap_replace(&smap_aaa, SYSTEM_AAA_FALLBACK, OPS_TRUE_STR);
    }
    else
    {
        smap_replace(&smap_aaa, SYSTEM_AAA_FALLBACK, OPS_FALSE_STR);
    }

    ovsrec_system_set_aaa(row, &smap_aaa);
    smap_destroy(&smap_aaa);

    txn_status = cli_do_config_finish(status_txn);

    if (txn_status == TXN_SUCCESS || txn_status == TXN_UNCHANGED)
    {
        return CMD_SUCCESS;
    }
    else
    {
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }
}

/* CLI to enable fallback to local authentication. */
DEFUN(cli_aaa_remove_fallback,
        aaa_remove_fallback_cmd,
        "aaa authentication login fallback error local",
        AAA_STR
        "User authentication\n"
        "Switch login\n"
        "Fallback authentication\n"
        "Radius server unreachable\n" "Local authentication (Default)")
{
    return aaa_fallback_option(OPS_TRUE_STR);
}

/* CLI to disable fallback to local authentication. */
DEFUN(cli_aaa_no_remove_fallback,
        aaa_no_remove_fallback_cmd,
        "no aaa authentication login fallback error local",
        NO_STR
        AAA_STR
        "User authentication\n"
        "Switch login\n"
        "Fallback authentication\n"
        "Radius server unreachable\n" "Local authentication (Default)")
{
    return aaa_fallback_option(OPS_FALSE_STR);
}

/* Displays AAA Authentication configuration.
 * Shows status of the local authentication [Enabled/Disabled]
 * Shows status of the Radius authentication [Enabled/Disabled]
 * If Radius authentication is enabled, shows Radius authentication
 * type [pap/chap]
 * Shows status of Fallback authenticaion to local [Enabled/Disabled]
 */
static int
aaa_show_aaa_authenctication()
{
    const struct ovsrec_system *row = NULL;

    row = ovsrec_system_first(idl);

    if (!row)
    {
        VLOG_ERR(OVSDB_ROW_FETCH_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    vty_out(vty, "AAA Authentication:%s", VTY_NEWLINE);

    if (!strcmp(smap_get(&row->aaa, SYSTEM_AAA_FALLBACK), OPS_TRUE_STR))
    {
        vty_out(vty, "  Fallback to local authentication\t: %s%s",
                "Enabled", VTY_NEWLINE);
    }
    else
    {
        vty_out(vty, "  Fallback to local authentication\t: %s%s",
                "Disabled", VTY_NEWLINE);
    }

    return show_aaa_authentication_priority_group();
}

static int
show_aaa_authentication_priority_group()
{
    int count = 0;
    const struct ovsrec_aaa_server_group *group_row = NULL;
    const struct ovsrec_aaa_server_group_prio *group_prio_list = NULL;

    group_prio_list = ovsrec_aaa_server_group_prio_first(idl);

    if (!group_prio_list)
    {
      return CMD_SUCCESS;
    }

    count = group_prio_list->n_authentication_group_prios;

    if (count > 1)
    {
        int idx = 0;
        char row_separator[AAA_TABLE_WIDTH + 1] = {};
        int64_t priority = 0;

        if (!ovsrec_aaa_server_group_first(idl))
        {
            return CMD_SUCCESS;
        }

        /* Create row seperator string*/
        for(idx = 0; idx < AAA_TABLE_WIDTH; idx++)
            row_separator[idx] = '-';
        row_separator[AAA_TABLE_WIDTH] = '\0';

        vty_out(vty, "%sDefault Authentication for All Channels:%s", VTY_NEWLINE, VTY_NEWLINE);
        vty_out(vty, "%s%s", row_separator, VTY_NEWLINE);
        vty_out(vty, "%-32s | %-14s%s", "GROUP NAME", "GROUP PRIORITY", VTY_NEWLINE);
        vty_out(vty, "%s%s", row_separator, VTY_NEWLINE);
        for(idx = 0; idx < count; idx ++)
        {
            priority = group_prio_list->key_authentication_group_prios[idx];
            group_row = group_prio_list->value_authentication_group_prios[idx];
            vty_out(vty, "%-32s | %-14ld%s", group_row->group_name, priority, VTY_NEWLINE);
        }
    }

    return CMD_SUCCESS;
}

/* CLI to show authentication mechanism configured in DB. */
DEFUN(cli_aaa_show_aaa_authenctication,
        aaa_show_aaa_authenctication_cmd,
        "show aaa authentication",
        SHOW_STR
        "Show authentication options\n" "Show aaa authentication information\n")
{
    return aaa_show_aaa_authenctication();
}

static int
show_aaa_server_groups(const char* group_type)
{
    const struct ovsrec_aaa_server_group *group_row = NULL;
    const struct ovsrec_tacacs_server *server_row = NULL;
    struct shash sorted_tacacs_servers;
    const struct shash_node **nodes;
    int count = 0;
    int idx = 0;
    bool by_default_priority = false;
    char row_separator[AAA_TABLE_WIDTH + 1] = {};

    if (!ovsrec_aaa_server_group_first(idl))
    {
        return CMD_SUCCESS;
    }

    /*TODO add radius server group table code*/
    shash_init(&sorted_tacacs_servers);

    OVSREC_TACACS_SERVER_FOR_EACH(server_row, idl)
    {
        shash_add(&sorted_tacacs_servers, server_row->ip_address, (void *)server_row);
    }

    nodes = sort_tacacs_server(&sorted_tacacs_servers, by_default_priority);
    count = shash_count(&sorted_tacacs_servers);

    group_row = ovsrec_aaa_server_group_first(idl);
    if (group_row == NULL) {
        vty_out(vty, "No AAA Server Group configured%s", VTY_NEWLINE);
        return CMD_SUCCESS;
    }

    /* Create row seperator string*/
    for(idx = 0; idx < AAA_TABLE_WIDTH; idx++)
        row_separator[idx] = '-';
    row_separator[AAA_TABLE_WIDTH] = '\0';

    vty_out(vty, "%s******* AAA Mechanism TACACS+ *******%s", VTY_NEWLINE, VTY_NEWLINE);

    vty_out(vty, "%s%s", row_separator, VTY_NEWLINE);
    vty_out(vty, "%-32s| %-45s| %-5s| %-8s%s","GROUP NAME", "SERVER NAME",
                                          "PORT", "PRIORITY", VTY_NEWLINE);
    vty_out(vty, "%s%s", row_separator, VTY_NEWLINE);

    OVSREC_AAA_SERVER_GROUP_FOR_EACH(group_row, idl)
    {
        bool empty_group = true;
        if (group_type && !VTYSH_STR_EQ(group_type, group_row->group_type))
        {
            continue;
        }

        if (VTYSH_STR_EQ(group_row->group_name, SYSTEM_AAA_TACACS_PLUS)
            || VTYSH_STR_EQ(group_row->group_name, SYSTEM_AAA_RADIUS)
            || VTYSH_STR_EQ(group_row->group_name, SYSTEM_AAA_LOCAL))
        {
            continue;
        }

        for(idx = 0; idx < count; idx++)
        {
            server_row = (const struct ovsrec_tacacs_server *)nodes[idx]->data;
            if (server_row->group == group_row)
            {
                empty_group = false;
                vty_out(vty, "%-32s| %-45s| %-5ld| %-ld%s", group_row->group_name,
                        server_row->ip_address, server_row->tcp_port,
                        server_row->group_priority, VTY_NEWLINE);
            }
        }
        if (!empty_group)
        {
            vty_out(vty, "%s%s", row_separator, VTY_NEWLINE);
        }
    }

    by_default_priority = true;
    free(nodes);
    nodes = NULL;
    nodes = sort_tacacs_server(&sorted_tacacs_servers, by_default_priority);

    /* print tacacs+ default group rows */
    if ((group_type && VTYSH_STR_EQ(group_type, SYSTEM_AAA_TACACS_PLUS))
        || !group_type)
    {
        const struct ovsrec_aaa_server_group *default_group = NULL;
        default_group = get_row_by_server_group_name(SYSTEM_AAA_TACACS_PLUS);
        bool empty_group = true;

        for(idx = 0; idx < count; idx++)
        {
            server_row = (const struct ovsrec_tacacs_server *)nodes[idx]->data;
            if (server_row->group == default_group)
            {
                empty_group = false;
                vty_out(vty, "%-11s %-20s| %-45s| %-5ld| %-8ld%s", default_group->group_name,
                        "(default)",
                        server_row->ip_address, server_row->tcp_port,
                        server_row->default_priority, VTY_NEWLINE);
            }
        }
        if (!empty_group)
        {
            vty_out(vty, "%s%s", row_separator, VTY_NEWLINE);
        }
    }
    shash_destroy(&sorted_tacacs_servers);
    free(nodes);
    return CMD_SUCCESS;
}

DEFUN(cli_show_aaa_server_groups,
      show_aaa_server_groups_cmd,
      "show aaa server-groups {radius | tacacs+}",
      SHOW_STR
      AAA_STR
      AAA_GROUP_HELP_STR
      RADIUS_HELP_STR
      TACACS_HELP_STR)
{
    if (argv[0] && VTYSH_STR_EQ(argv[0], SYSTEM_AAA_RADIUS))
        return show_aaa_server_groups(argv[0]);
    return show_aaa_server_groups(argv[1]);
}

const int
aaa_server_group_sanitize_parameters(aaa_server_group_params_t *server_group_params)
{
   /* validate server group name*/
   if (strlen(server_group_params->group_name) > MAX_CHARS_IN_SERVER_GROUP_NAME)
   {
        vty_out(vty, "Server group name should be less than %d characters%s",
                MAX_CHARS_IN_SERVER_GROUP_NAME, VTY_NEWLINE);
        return CMD_ERR_NOTHING_TODO;
   }

   /*Prevent user from configure default group*/
   if ((strcmp(server_group_params->group_name, SYSTEM_AAA_RADIUS) == 0) ||
       (strcmp(server_group_params->group_name, SYSTEM_AAA_TACACS_PLUS) == 0) ||
       (strcmp(server_group_params->group_name, SYSTEM_AAA_LOCAL) == 0))
   {
        vty_out(vty, "Invalid server group name%s", VTY_NEWLINE);
        return CMD_ERR_NOTHING_TODO;
   }

   if ((strcmp(server_group_params->group_type, SYSTEM_AAA_RADIUS) != 0) &&
       (strcmp(server_group_params->group_type, SYSTEM_AAA_TACACS_PLUS) != 0))
   {
        vty_out(vty, "Invalid server group type%s", VTY_NEWLINE);
        return CMD_ERR_NOTHING_TODO;
   }

   return CMD_SUCCESS;
}

/* Create/remove RADIUS or TACACS+ server-groups */
static int
configure_aaa_server_group(aaa_server_group_params_t *server_group_params)
{
    const struct ovsrec_aaa_server_group *row = NULL;
    struct ovsdb_idl_txn *server_group_txn = NULL;

    int retVal = aaa_server_group_sanitize_parameters(server_group_params);
    if (retVal != CMD_SUCCESS)
    {
        return retVal;
    }

    /* Start of transaction */
    START_DB_TXN(server_group_txn);

    /* See if specified AAA server group already exists */
    row = get_row_by_server_group_name(server_group_params->group_name);
    if (row == NULL)
    {
        if (server_group_params->no_form)
        {
            /* aaa server group does not exist */
            vty_out(vty, "AAA server group %s does not exist%s",
                         server_group_params->group_name, VTY_NEWLINE);
        }
        else
        {
            bool is_static_group = AAA_SERVER_GROUP_IS_STATIC_DEFAULT;
            row = ovsrec_aaa_server_group_insert(server_group_txn);
            if (row == NULL)
            {
                VLOG_ERR("Could not insert a row into AAA Server Group Table\n");
                ERRONEOUS_DB_TXN(server_group_txn,
                         "Could not insert a row into AAA Server Group Table");
            }

            VLOG_DBG("SUCCESS: Inserted a row into AAA Server Group Table\n");
            ovsrec_aaa_server_group_set_group_name(row, server_group_params->group_name);
            ovsrec_aaa_server_group_set_group_type(row, server_group_params->group_type);
            ovsrec_aaa_server_group_set_is_static(row, is_static_group);
        }
    }
    else
    {
        if (server_group_params->no_form)
        {
            const struct ovsrec_tacacs_server *row_iter = NULL;
            const struct ovsrec_aaa_server_group *default_group = NULL;
            const struct ovsrec_aaa_server_group_prio *group_prio_list = NULL;
            const char* group_name = row->group_type;
            default_group = get_row_by_server_group_name(group_name);
            VLOG_DBG("Moving servers from server group %s to default", row->group_name);

            OVSREC_TACACS_SERVER_FOR_EACH(row_iter, idl) {
                if (row == row_iter->group)
                {
                    ovsrec_tacacs_server_set_group_priority(row_iter,
                                                            TACACS_SERVER_GROUP_PRIORITY_DEFAULT);
                    ovsrec_tacacs_server_set_group(row_iter, default_group);
                }
            }

            /* Update aaa_server_group_prio list*/
            group_prio_list = ovsrec_aaa_server_group_prio_first(idl);
            if (group_prio_list == NULL)
            {
                ERRONEOUS_DB_TXN(server_group_txn,
                                  "Could not access 'default' entry of AAA_Server_Group_Prio Table");
            }
            else if (group_prio_list->n_authentication_group_prios > 1)
            {
                int iter = 0;
                int skip = 0;
                int list_count = group_prio_list->n_authentication_group_prios;
                int64_t *key_list = xmalloc(sizeof(int64_t) * list_count);
                struct ovsrec_aaa_server_group **value_list =
                                      xmalloc(sizeof(*row) * list_count);
                for (iter = 0; iter < list_count; iter++)
                {
                   if (row == group_prio_list->value_authentication_group_prios[iter])
                   {
                       skip = 1;
                       continue;
                   }
                   if (skip)
                   {
                       key_list[iter - skip] =
                           group_prio_list->key_authentication_group_prios[iter] - 1;
                       value_list[iter - skip] =
                           group_prio_list->value_authentication_group_prios[iter];
                   }
                   else
                   {
                       key_list[iter] = group_prio_list->key_authentication_group_prios[iter];
                       value_list[iter] = group_prio_list->value_authentication_group_prios[iter];
                   }
                }

                ovsrec_aaa_server_group_prio_set_authentication_group_prios(group_prio_list,
                                                                            key_list, value_list,
                                                                            list_count - 1);
                free(key_list);
                free(value_list);
            }

            VLOG_DBG("Deleting server group %s from AAA Server Group table", row->group_name);
            ovsrec_aaa_server_group_delete(row);
        }
    }
    /* End of transaction. */
    END_DB_TXN(server_group_txn);
}

/* CLI to create AAA TACACS+ server group  */
DEFUN (cli_aaa_create_tacacs_server_group,
       aaa_create_tacacs_server_group_cmd,
       "aaa group server (radius | tacacs+) WORD",
       AAA_STR
       AAA_GROUP_HELP_STR
       AAA_SERVER_TYPE_HELP_STR
       RADIUS_HELP_STR
       TACACS_HELP_STR
       AAA_GROUP_NAME_HELP_STR)
{
    int result = CMD_SUCCESS;
    char *group_type = NULL;
    static char group_name[MAX_CHARS_IN_SERVER_GROUP_NAME];
    aaa_server_group_params_t aaa_server_group_params;

    if (strcmp("radius", argv[0]) == 0)
    {
        vty_out(vty, "Radius server group not supported yet%s", VTY_NEWLINE);
        return CMD_ERR_NOTHING_TODO;
    }
    else
    {
        group_type = SYSTEM_AAA_TACACS_PLUS;
    }

    aaa_server_group_params.group_type = group_type;
    aaa_server_group_params.group_name = (char *)argv[1];
    aaa_server_group_params.no_form = false;

    if (vty_flags & CMD_FLAG_NO_CMD)
    {
        aaa_server_group_params.no_form = true;
    }
    result =  configure_aaa_server_group(&aaa_server_group_params);
    if (result != CMD_SUCCESS)
        return result;
    if (!aaa_server_group_params.no_form)
    {
        vty->node = AAA_SERVER_GROUP_NODE;
        strncpy(group_name, argv[1], MAX_CHARS_IN_SERVER_GROUP_NAME);
        vty->index = group_name;
    }
   return CMD_SUCCESS;
}

DEFUN_NO_FORM (cli_aaa_create_tacacs_server_group,
               aaa_create_tacacs_server_group_cmd,
               "aaa group server (radius | tacacs+) WORD",
               AAA_STR
               AAA_GROUP_HELP_STR
               AAA_SERVER_TYPE_HELP_STR
               RADIUS_HELP_STR
               TACACS_HELP_STR
               AAA_GROUP_NAME_HELP_STR);

static const struct ovsrec_tacacs_server*
get_tacacs_server_by_name_port(const char *server_name, int64_t auth_port)
{
    const struct ovsrec_tacacs_server *row = NULL;
    OVSREC_TACACS_SERVER_FOR_EACH(row, idl) {
        if (!strcmp(row->ip_address, server_name)
            && (row->tcp_port == auth_port)) {
            return row;
        }
    }
    return NULL;
}

static int
configure_aaa_server_group_add_server(aaa_server_group_params_t *server_group_params,
                                      char* server_name, int64_t port)
{
    const struct ovsrec_aaa_server_group *group_row = NULL;
    struct ovsdb_idl_txn* status_txn = NULL;

    START_DB_TXN(status_txn);

    /* See if specified AAA server group already exists */
    group_row = get_row_by_server_group_name(server_group_params->group_name);
    if (group_row == NULL)
    {
        /* aaa server group does not exist */
        ERRONEOUS_DB_TXN(status_txn, "AAA server group does not exist!");
    }

    /*TODO add code for radius group as well*/
    if (strcmp(group_row->group_type, SYSTEM_AAA_RADIUS) == 0)
    {
        vty_out(vty, "RADIUS server group not supported yet%s", VTY_NEWLINE);
    }
    else if (strcmp(group_row->group_type, SYSTEM_AAA_TACACS_PLUS) == 0)
    {
        const struct ovsrec_tacacs_server *server_row = NULL;
        const struct ovsrec_aaa_server_group *default_group = NULL;
        const char *tacacs_group = SYSTEM_AAA_TACACS_PLUS;
        default_group = get_row_by_server_group_name(tacacs_group);
        /* See if specified TACACS+ server exist */
        server_row = get_tacacs_server_by_name_port(server_name, port);
        if (server_row == NULL)
        {
           /* Server does not exist*/
           ERRONEOUS_DB_TXN(status_txn, "TACACS+ server does not exist!");
        }

        /* Remove server from group */
        if (server_group_params->no_form)
        {
            ovsrec_tacacs_server_set_group_priority(server_row,
                                                    TACACS_SERVER_GROUP_PRIORITY_DEFAULT);
            ovsrec_tacacs_server_set_group(server_row, default_group);
        }
        /* Add server to group */
        else
        {
            /* User not allowed to directly move server from user defined group*/
            if (server_row->group != default_group)
            {
               ERRONEOUS_DB_TXN(status_txn, "TACACS+ server already assigned to a group!");
            }
            else
            {
                const struct ovsrec_tacacs_server *row_iter = NULL;
                int64_t group_priority = 0;
                OVSREC_TACACS_SERVER_FOR_EACH(row_iter, idl) {
                    /* get the new group maximum priority */
                    if ((group_row == row_iter->group) &&
                        (group_priority < row_iter->group_priority))
                    {
                        group_priority = row_iter->group_priority;
                    }
                }
                ++group_priority;
                ovsrec_tacacs_server_set_group_priority(server_row, group_priority);
                ovsrec_tacacs_server_set_group(server_row, group_row);
            }
        }
    }
    /* End of transaction. */
    END_DB_TXN(status_txn);
}

/* CLI to add/remove AAA server to server group  */
DEFUN (aaa_group_add_server,
       aaa_group_add_server_cmd,
       "server WORD {port <1-65535>}",
       AAA_SERVER_HELP_STR
       AAA_SERVER_NAME_HELP_STR
       AUTH_PORT_HELP_STR
       AUTH_PORT_RANGE_HELP_STR)
{
    char *server_name = (char *)argv[0];
    int64_t port = TACACS_SERVER_TCP_PORT_DEFAULT;
    aaa_server_group_params_t aaa_server_group_params;
    aaa_server_group_params.group_name = (char *)vty->index;
    aaa_server_group_params.no_form = false;
    if ((argc == 2) && argv[1])
        port = atoi(argv[1]);

    if (vty_flags & CMD_FLAG_NO_CMD)
    {
        aaa_server_group_params.no_form = true;
    }
    return configure_aaa_server_group_add_server(&aaa_server_group_params, server_name, port);
}

DEFUN_NO_FORM (aaa_group_add_server,
               aaa_group_add_server_cmd,
               "server WORD {port <1-65535>}",
               AAA_SERVER_HELP_STR
               AAA_SERVER_NAME_HELP_STR
               AUTH_PORT_HELP_STR
               AUTH_PORT_RANGE_HELP_STR);

/* Specifies the TACACS+ server global configuration*/
/*
 * Modify TACACS+ server global auth-type
 * default 'auth-type' is 'pap'
 */
static int
tacacs_set_global_auth_type(const char *auth_type)
{
    const struct ovsrec_system *ovs_system = NULL;
    struct ovsdb_idl_txn *tacacs_txn = NULL;
    struct smap smap_aaa;

    /* Start of transaction */
    START_DB_TXN(tacacs_txn);

    ovs_system = ovsrec_system_first(idl);

    if (ovs_system == NULL)
    {
        ERRONEOUS_DB_TXN(tacacs_txn, "Could not access the System Table");
    }

    smap_clone(&smap_aaa, &ovs_system->aaa);

    smap_replace(&smap_aaa, SYSTEM_AAA_TACACS_AUTH, auth_type);

    ovsrec_system_set_aaa(ovs_system, &smap_aaa);

    smap_destroy(&smap_aaa);

    /* End of transaction */
    END_DB_TXN(tacacs_txn);
}


/*
 * CLI to configure the shared secret key between the TACACS+ client
 * and the TACACS+ server, default value is 'testing123-1'
 */
DEFUN(cli_tacacs_server_set_auth_type,
      tacacs_server_set_auth_type_cmd,
      "tacacs-server auth-type ( pap | chap)",
      TACACS_SERVER_HELP_STR
      AAA_AUTH_TYPE_HELP_STR
      AUTH_TYPE_PAP_HELP_STR
      AUTH_TYPE_CHAP_HELP_STR)
{
    if (vty_flags & CMD_FLAG_NO_CMD)
        return tacacs_set_global_auth_type(TACACS_SERVER_AUTH_TYPE_DEFAULT);

    return tacacs_set_global_auth_type(argv[0]);
}

DEFUN_NO_FORM(cli_tacacs_server_set_auth_type,
              tacacs_server_set_auth_type_cmd,
              "tacacs-server auth-type",
              TACACS_SERVER_HELP_STR
              AAA_AUTH_TYPE_HELP_STR);

/*
 * Modify TACACS+ server global passkey
 * default 'passkey' is 'testing123-1'
 */
static int
tacacs_set_global_passkey(const char *passkey)
{
    const struct ovsrec_system *ovs_system = NULL;
    struct ovsdb_idl_txn *tacacs_txn = NULL;
    struct smap smap_aaa;

    /* validate the length of passkey */
    if (strlen(passkey) > MAX_LENGTH_TACACS_PASSKEY)
    {
        vty_out(vty, "Length of passkey should be less than 64%s", VTY_NEWLINE);
        return CMD_ERR_NOTHING_TODO;
    }

    /* Start of transaction */
    START_DB_TXN(tacacs_txn);

    ovs_system = ovsrec_system_first(idl);

    if (ovs_system == NULL)
    {
        ERRONEOUS_DB_TXN(tacacs_txn, "Could not access the System Table");
    }

    smap_clone(&smap_aaa, &ovs_system->aaa);

    smap_replace(&smap_aaa, SYSTEM_AAA_TACACS_PASSKEY, passkey);

    ovsrec_system_set_aaa(ovs_system, &smap_aaa);

    smap_destroy(&smap_aaa);

    /* End of transaction */
    END_DB_TXN(tacacs_txn);
}

/*
 * CLI to configure the shared secret key between the TACACS+ client
 * and the TACACS+ server, default value is 'testing123-1'
 */
DEFUN(cli_tacacs_server_set_passkey,
      tacacs_server_set_passkey_cmd,
      "tacacs-server key WORD",
      TACACS_SERVER_HELP_STR
      SHARED_KEY_HELP_STR
      SHARED_KEY_VAL_HELP_STR)
{
    if (vty_flags & CMD_FLAG_NO_CMD)
        return tacacs_set_global_passkey(TACACS_SERVER_PASSKEY_DEFAULT);

    return tacacs_set_global_passkey(argv[0]);
}

DEFUN_NO_FORM(cli_tacacs_server_set_passkey,
              tacacs_server_set_passkey_cmd,
              "tacacs-server key",
              TACACS_SERVER_HELP_STR
              SHARED_KEY_HELP_STR);

/*
 * Modify TACACS+ server global TCP port
 * default 'port' is 49
 */
static int
tacacs_set_global_port(const char *port)
{
    const struct ovsrec_system *ovs_system = NULL;
    struct ovsdb_idl_txn *tacacs_txn = NULL;
    struct smap smap_aaa;

    /* Start of transaction */
    START_DB_TXN(tacacs_txn);

    ovs_system = ovsrec_system_first(idl);

    if (ovs_system == NULL)
    {
        ERRONEOUS_DB_TXN(tacacs_txn, "Could not access the System Table");
    }

    smap_clone(&smap_aaa, &ovs_system->aaa);

    smap_replace(&smap_aaa, SYSTEM_AAA_TACACS_TCP_PORT, port);

    ovsrec_system_set_aaa(ovs_system, &smap_aaa);

    smap_destroy(&smap_aaa);

    /* End of transaction */
    END_DB_TXN(tacacs_txn);
}

/*
 * CLI to configure the TCP port number used for exchanging TACACS+
 * messages between the client and server. Default TCP port number is 49
 */
DEFUN(cli_tacacs_server_set_port,
      tacacs_server_set_port_cmd,
      "tacacs-server port <1-65535>",
      TACACS_SERVER_HELP_STR
      AUTH_PORT_HELP_STR
      AUTH_PORT_RANGE_HELP_STR)
{
    if (vty_flags & CMD_FLAG_NO_CMD)
        return tacacs_set_global_port(TACACS_SERVER_TCP_PORT_DEFAULT_VAL);

    return tacacs_set_global_port(argv[0]);
}

DEFUN_NO_FORM (cli_tacacs_server_set_port,
               tacacs_server_set_port_cmd,
               "tacacs-server port",
               TACACS_SERVER_HELP_STR
               AUTH_PORT_HELP_STR);

/*
 * Modify TACACS+ server global timeout
 * default 'timeout' is 5
 */
static int
tacacs_set_global_timeout(const char *timeout)
{
    const struct ovsrec_system *ovs_system = NULL;
    struct ovsdb_idl_txn *tacacs_txn = NULL;
    struct smap smap_aaa;

    /* Start of transaction */
    START_DB_TXN(tacacs_txn);

    ovs_system = ovsrec_system_first(idl);

    if (ovs_system == NULL)
    {
        ERRONEOUS_DB_TXN(tacacs_txn, "Could not access the System Table");
    }

    smap_clone(&smap_aaa, &ovs_system->aaa);

    smap_replace(&smap_aaa, SYSTEM_AAA_TACACS_TIMEOUT, timeout);

    ovsrec_system_set_aaa(ovs_system, &smap_aaa);

    smap_destroy(&smap_aaa);

    /* End of transaction */
    END_DB_TXN(tacacs_txn);
}

/*
 * CLI to configure the timeout interval that the switch waits
 * for response from the TACACS+ server before issue a timeout failure.
 * Default timeout value is 5 seconds
 */
DEFUN(cli_tacacs_server_set_timeout,
      tacacs_server_set_timeout_cmd,
      "tacacs-server timeout <1-60>",
      TACACS_SERVER_HELP_STR
      TIMEOUT_HELP_STR
      TIMEOUT_RANGE_HELP_STR)
{
    if (vty_flags & CMD_FLAG_NO_CMD)
        return tacacs_set_global_timeout(TACACS_SERVER_TIMEOUT_DEFAULT_VAL);

    return tacacs_set_global_timeout(argv[0]);
}

DEFUN_NO_FORM(cli_tacacs_server_set_timeout,
              tacacs_server_set_timeout_cmd,
              "tacacs-server timeout",
              TACACS_SERVER_HELP_STR
              TIMEOUT_HELP_STR);

/* Adding RADIUS server host.
 * Add the host 'ipv4' with default values
 * default 'udp_port' is 1812
 * default 'retries' is 1
 * default 'timeout' is 5 sec
 * default 'passskey' is testing123-1
 */
static int
radius_server_add_host(const char *ipv4)
{
    const char *passkey = RADIUS_SERVER_DEFAULT_PASSKEY;
    struct ovsrec_radius_server *row = NULL;
    int64_t udp_port = 0, timeout = 0, retries = 0, i = 0, priority = 1;
    const struct ovsrec_radius_server *tempRow = NULL, **radius_info = NULL;
    const struct ovsrec_system *ovs = NULL;
    struct in_addr addr;
    struct ovsdb_idl_txn *status_txn = NULL;
    enum ovsdb_idl_txn_status txn_status;

    if (inet_pton(AF_INET, ipv4, &addr) <= 0)
    {
        vty_out(vty, "Invalid IPv4 address%s", VTY_NEWLINE);
        cli_do_config_abort(status_txn);
        return CMD_ERR_NOTHING_TODO;
    }

    if (!IS_VALID_IPV4(htonl(addr.s_addr)))
    {
        vty_out(vty,
                "Broadcast, multicast and loopback addresses are not allowed.%s",
                VTY_NEWLINE);
        cli_do_config_abort(status_txn);
        return CMD_ERR_NOTHING_TODO;
    }

    udp_port = RADIUS_SERVER_DEFAULT_PORT;
    timeout = RADIUS_SERVER_DEFAULT_TIMEOUT;
    retries = RADIUS_SERVER_DEFAULT_RETRIES;

    status_txn = cli_do_config_start();

    if (status_txn == NULL)
    {
        VLOG_ERR(OVSDB_TXN_CREATE_ERROR);
        cli_do_config_abort(status_txn);
        return CMD_OVSDB_FAILURE;
    }

    OVSREC_RADIUS_SERVER_FOR_EACH(tempRow, idl)
    {
        if (!strcmp(tempRow->ip_address, ipv4))
        {
            cli_do_config_abort(status_txn);
            status_txn = NULL;
            return CMD_SUCCESS;
        }
        retries = *(tempRow->retries);
        timeout = *(tempRow->timeout);
        priority += 1;
    }

    ovs = ovsrec_system_first(idl);
    if (ovs == NULL)
    {
        assert(0);
        cli_do_config_abort(status_txn);
        status_txn = NULL;
        return CMD_OVSDB_FAILURE;
    }
    if (ovs->n_radius_servers == MAX_RADIUS_SERVERS)
    {
        vty_out(vty, "Exceeded maximum radius servers support%s", VTY_NEWLINE);
        cli_do_config_abort(status_txn);
        status_txn = NULL;
        return CMD_OVSDB_FAILURE;
    }

    row = ovsrec_radius_server_insert(status_txn);

    ovsrec_radius_server_set_ip_address(row, ipv4);
    ovsrec_radius_server_set_passkey(row, passkey);
    ovsrec_radius_server_set_udp_port(row, &udp_port, 1);
    ovsrec_radius_server_set_retries(row, &retries, 1);
    ovsrec_radius_server_set_timeout(row, &timeout, 1);
    ovsrec_radius_server_set_priority(row, priority);

    radius_info =
        xmalloc(sizeof *ovs->radius_servers * (ovs->n_radius_servers + 1));
    for (i = 0; i < ovs->n_radius_servers; i++)
    {
        radius_info[i] = ovs->radius_servers[i];
    }
    radius_info[ovs->n_radius_servers] = row;
    ovsrec_system_set_radius_servers(ovs,
            (struct ovsrec_radius_server **)
            radius_info,
            ovs->n_radius_servers + 1);
    free(radius_info);

    txn_status = cli_do_config_finish(status_txn);

    if (txn_status == TXN_SUCCESS || txn_status == TXN_UNCHANGED)
    {
        return CMD_SUCCESS;
    }
    else
    {
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }
}

/* CLI to add host */
DEFUN(cli_radius_server_add_host,
        radius_server_add_host_cmd,
        "radius-server host A.B.C.D",
        "Radius server configuration\n"
        "Host IP address\n" "Radius server IPv4 address\n")
{
    return radius_server_add_host(argv[0]);
}

/* Removes RADIUS server authentication port.
 * On success removes configured 'auth-port' and sets to default 'auth-port' 1812.
 */
static int
radius_server_remove_auth_port(const char *ipv4, const char *authport)
{
    int64_t port = atoi(authport);
    int64_t default_udp_port = RADIUS_SERVER_DEFAULT_PORT;
    const struct ovsrec_radius_server *tempRow = NULL;
    struct ovsdb_idl_txn *status_txn = cli_do_config_start();
    struct in_addr addr;
    enum ovsdb_idl_txn_status txn_status;

    if (status_txn == NULL)
    {
        VLOG_ERR(OVSDB_TXN_CREATE_ERROR);
        cli_do_config_abort(status_txn);
        return CMD_OVSDB_FAILURE;
    }

    if (inet_pton(AF_INET, ipv4, &addr) <= 0)
    {
        vty_out(vty, "Invalid IPv4 address%s", VTY_NEWLINE);
        cli_do_config_abort(status_txn);
        return CMD_ERR_NOTHING_TODO;
    }

    if (!IS_VALID_IPV4(htonl(addr.s_addr)))
    {
        vty_out(vty,
                "Broadcast, multicast and loopback addresses are not allowed.%s",
                VTY_NEWLINE);
        cli_do_config_abort(status_txn);
        return CMD_ERR_NOTHING_TODO;
    }

    OVSREC_RADIUS_SERVER_FOR_EACH(tempRow, idl)
    {
        if (!strcmp(tempRow->ip_address, ipv4))
        {
            break;
        }
    }

    if (!tempRow)
    {
        vty_out(vty, "No radius server configured with IP %s %s", ipv4,
                VTY_NEWLINE);
        VLOG_ERR(OVSDB_ROW_FETCH_ERROR);
        cli_do_config_abort(status_txn);
        return CMD_ERR_NOTHING_TODO;
    }
    if (*(tempRow->udp_port) != port)
    {
        vty_out(vty, " Wrong authentication port%s", VTY_NEWLINE);
        cli_do_config_abort(status_txn);
        return CMD_ERR_NOTHING_TODO;
    }

    ovsrec_radius_server_set_udp_port(tempRow, &default_udp_port, 1);
    txn_status = cli_do_config_finish(status_txn);

    if (txn_status == TXN_SUCCESS || txn_status == TXN_UNCHANGED)
    {
        return CMD_SUCCESS;
    }
    else
    {
        VLOG_ERR
            ("Commiting transaction to DB failed in function=%s, line=%d \n",
                    __func__, __LINE__);
        return CMD_OVSDB_FAILURE;
    }

}

DEFUN(cli_radius_server_remove_auth_port,
        radius_server_remove_auth_port_cmd,
        "no radius-server host A.B.C.D auth-port <0-65535>",
        NO_STR
        "Radius server configuration\n"
        "Host IP address\n"
        "Radius server IPv4 address\n"
        "Set authentication port\n"
        "UDP port range is 0 to 65535. (Default: 1812)\n")
{
    return radius_server_remove_auth_port(argv[0], argv[1]);
}

/* Removes RADIUS server secret key.
 * On success removes configured 'passkey' and sets 'passkey'
 * to default value testing123-1.
 */
static int
radius_server_remove_passkey(const char *ipv4, const char *passkey)
{
    const char *default_passkey = RADIUS_SERVER_DEFAULT_PASSKEY;
    const struct ovsrec_radius_server *tempRow = NULL;
    struct ovsdb_idl_txn *status_txn = cli_do_config_start();
    struct in_addr addr;
    enum ovsdb_idl_txn_status txn_status;

    if (status_txn == NULL)
    {
        VLOG_ERR(OVSDB_TXN_CREATE_ERROR);
        cli_do_config_abort(status_txn);
        return CMD_OVSDB_FAILURE;
    }

    if (inet_pton(AF_INET, ipv4, &addr) <= 0)
    {
        vty_out(vty, "Invalid IPv4 address%s", VTY_NEWLINE);
        cli_do_config_abort(status_txn);
        return CMD_ERR_NOTHING_TODO;
    }

    if (!IS_VALID_IPV4(htonl(addr.s_addr)))
    {
        vty_out(vty,
                "Broadcast, multicast and loopback addresses are not allowed.%s",
                VTY_NEWLINE);
        cli_do_config_abort(status_txn);
        return CMD_ERR_NOTHING_TODO;
    }

    OVSREC_RADIUS_SERVER_FOR_EACH(tempRow, idl)
    {
        if (!strcmp(tempRow->ip_address, ipv4))
        {
            break;
        }
    }

    if (!tempRow)
    {
        vty_out(vty, "No radius server configured with IP %s %s", ipv4,
                VTY_NEWLINE);
        VLOG_ERR(OVSDB_ROW_FETCH_ERROR);
        cli_do_config_abort(status_txn);
        return CMD_OVSDB_FAILURE;
    }
    if (strcmp(tempRow->passkey, passkey))
    {
        vty_out(vty, " passkey mismatched%s", VTY_NEWLINE);
        cli_do_config_abort(status_txn);
        return CMD_ERR_NOTHING_TODO;
    }
    ovsrec_radius_server_set_passkey(tempRow, default_passkey);

    txn_status = cli_do_config_finish(status_txn);

    if (txn_status == TXN_SUCCESS || txn_status == TXN_UNCHANGED)
    {
        return CMD_SUCCESS;
    }
    else
    {
        VLOG_ERR
            ("Commiting transaction to DB failed in function=%s, line=%d \n",
                    __func__, __LINE__);
        return CMD_OVSDB_FAILURE;
    }

}

DEFUN(cli_radius_server_remove_passkey,
        radius_server_remove_passkey_cmd,
        "no radius-server host A.B.C.D key WORD",
        NO_STR
        "Radius server configuration\n"
        "Host IP address\n"
        "Radius server IPv4 address\n"
        "Set shared secret\n" "Radius shared secret. (Default: testing123-1)\n")
{
    return radius_server_remove_passkey(argv[0], argv[1]);
}

/* Removes RADIUS server host. */
static int
radius_server_remove_host(const char *ipv4)
{
    int n = 0;
    int  i = 0;
    int64_t priority = 0;
    const struct ovsrec_radius_server *row = NULL, *tempRow = NULL;
    const struct ovsrec_radius_server **radius_info = NULL;
    const struct ovsrec_system *ovs = NULL;
    struct ovsdb_idl_txn *status_txn = cli_do_config_start();
    struct in_addr addr;
    enum ovsdb_idl_txn_status txn_status;

    if (status_txn == NULL)
    {
        VLOG_ERR(OVSDB_TXN_CREATE_ERROR);
        cli_do_config_abort(status_txn);
        return CMD_OVSDB_FAILURE;
    }

    if (inet_pton(AF_INET, ipv4, &addr) <= 0)
    {
        vty_out(vty, "Invalid IPv4 address%s", VTY_NEWLINE);
        cli_do_config_abort(status_txn);
        return CMD_ERR_NOTHING_TODO;
    }

    if (!IS_VALID_IPV4(htonl(addr.s_addr)))
    {
        vty_out(vty,
                "Broadcast, multicast and loopback addresses are not allowed.%s",
                VTY_NEWLINE);
        cli_do_config_abort(status_txn);
        return CMD_ERR_NOTHING_TODO;
    }

    OVSREC_RADIUS_SERVER_FOR_EACH(row, idl)
    {
        if (!strcmp(row->ip_address, ipv4))
        {
            tempRow = row;
            break;
        }
    }

    if (!tempRow)
    {
        vty_out(vty, "No radius server configured with IP %s %s", ipv4,
                VTY_NEWLINE);
        VLOG_ERR(OVSDB_ROW_FETCH_ERROR);
        cli_do_config_abort(status_txn);
        return CMD_OVSDB_FAILURE;
    }
    else
    {
        OVSREC_RADIUS_SERVER_FOR_EACH(row, idl)
        {
            if (tempRow->priority < row->priority)
            {
                priority = row->priority - 1;
                ovsrec_radius_server_set_priority(row, priority);
            }
        }
    }

    ovs = ovsrec_system_first(idl);

    ovsrec_radius_server_delete(tempRow);
    radius_info = xmalloc(sizeof *ovs->radius_servers * ovs->n_radius_servers);

    for (i = n = 0; i < ovs->n_radius_servers; i++)
    {
        if (ovs->radius_servers[i] != tempRow)
        {
            radius_info[n++] = ovs->radius_servers[i];
        }
    }
    ovsrec_system_set_radius_servers(ovs,
            (struct ovsrec_radius_server **)
            radius_info, n);
    free(radius_info);

    txn_status = cli_do_config_finish(status_txn);

    if (txn_status == TXN_SUCCESS || txn_status == TXN_UNCHANGED)
    {
        return CMD_SUCCESS;
    }
    else
    {
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }
}

/* CLI to remove radius server */
DEFUN(cli_radius_server_remove_host,
        radius_server_remove_host_cmd,
        "no radius-server host A.B.C.D",
        NO_STR
        "Radius server configuration\n"
        "Host IP address\n" "Radius server IPv4 address\n")
{
    return radius_server_remove_host(argv[0]);
}

/* Set secret key for the host.
 * On Success set 'passkey' to the host 'ipv4'.
 * On failure, returns CMD_OVSDB_FAILURE.
 */
static int
radius_server_passkey_host(const char *ipv4, const char *passkey)
{
    const struct ovsrec_radius_server *row = NULL;
    int ret = 0;
    enum ovsdb_idl_txn_status txn_status;
    struct ovsdb_idl_txn *status_txn = NULL;
    ret = radius_server_add_host(ipv4);
    if (CMD_SUCCESS != ret)
    {
        return ret;
    }
    status_txn = cli_do_config_start();
    if (status_txn == NULL)
    {
        VLOG_ERR(OVSDB_TXN_CREATE_ERROR);
        cli_do_config_abort(status_txn);
        return CMD_OVSDB_FAILURE;
    }
    OVSREC_RADIUS_SERVER_FOR_EACH(row, idl)
    {
        if (!strcmp(row->ip_address, ipv4))
        {
            ovsrec_radius_server_set_passkey(row, passkey);
        }
    }

    txn_status = cli_do_config_finish(status_txn);

    if (txn_status == TXN_SUCCESS || txn_status == TXN_UNCHANGED)
    {
        return CMD_SUCCESS;
    }
    else
    {
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }
}

/* CLI to set passkey */
DEFUN(cli_radius_server_passkey_host,
        radius_server_passkey_host_cmd,
        "radius-server host A.B.C.D key WORD",
        "Radius server configuration\n"
        "Host IP address\n"
        "Radius server IPv4 address\n"
        "Set shared secret\n" "Radius shared secret. (Default: testing123-1)\n")
{
    return radius_server_passkey_host(argv[0], argv[1]);
}

/* Set RADIUS server 'retries'.
 * On Success set 'retries' to the all host.
 * On failure, returns CMD_OVSDB_FAILURE.
 */
static int
radius_server_set_retries(const char *retries)
{
    int64_t val = atoi(retries);
    const struct ovsrec_radius_server *row = NULL;
    enum ovsdb_idl_txn_status txn_status;
    struct ovsdb_idl_txn *status_txn = cli_do_config_start();

    if (status_txn == NULL)
    {
        VLOG_ERR(OVSDB_TXN_CREATE_ERROR);
        cli_do_config_abort(status_txn);
        return CMD_OVSDB_FAILURE;
    }

    row = ovsrec_radius_server_first(idl);

    if (!row)
    {
        vty_out(vty, "No radius servers configured %s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_ROW_FETCH_ERROR);
        cli_do_config_abort(status_txn);
        return CMD_OVSDB_FAILURE;
    }

    OVSREC_RADIUS_SERVER_FOR_EACH(row, idl)
    {
        ovsrec_radius_server_set_retries(row, &val, 1);
    }

    txn_status = cli_do_config_finish(status_txn);

    if (txn_status == TXN_SUCCESS || txn_status == TXN_UNCHANGED)
    {
        return CMD_SUCCESS;
    }
    else
    {
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }
}

DEFUN(cli_radius_server_retries,
        radius_server_retries_cmd,
        "radius-server retries <0-5>",
        "Radius server configuration\n"
        "Set the number of retries\n"
        "Set the range from 0 to 5. (Default: 1)\n")
{
    return radius_server_set_retries(argv[0]);
}


/* Removes the RADIUS server configured 'retries' values
 * and sets to default 'retries' value 1.
 * On failure, returns CMD_OVSDB_FAILURE.
 */
static int
radius_server_remove_retries(const char *retries_t)
{
    int64_t retries,retry;
    retry = atoi(retries_t);
    const struct ovsrec_radius_server *tempRow = NULL;
    struct ovsdb_idl_txn *status_txn = cli_do_config_start();
    enum ovsdb_idl_txn_status txn_status;

    if (status_txn == NULL)
    {
        VLOG_ERR(OVSDB_TXN_CREATE_ERROR);
        cli_do_config_abort(status_txn);
        return CMD_OVSDB_FAILURE;
    }
    retries = RADIUS_SERVER_DEFAULT_RETRIES;

    tempRow = ovsrec_radius_server_first(idl);
    if (*(tempRow->retries) == retry)
    {
        OVSREC_RADIUS_SERVER_FOR_EACH(tempRow, idl)
        {
            ovsrec_radius_server_set_retries(tempRow, &retries, 1);
        }
    }
    else
    {
        vty_out(vty, "Mismatched retries value%s", VTY_NEWLINE);
        cli_do_config_abort(status_txn);
        return CMD_SUCCESS;
    }

    txn_status = cli_do_config_finish(status_txn);

    if (txn_status == TXN_SUCCESS || txn_status == TXN_UNCHANGED)
    {
        return CMD_SUCCESS;
    }
    else
    {
        VLOG_ERR
            ("Commiting transaction to DB failed in function=%s, line=%d \n",
                    __func__, __LINE__);
        return CMD_OVSDB_FAILURE;
    }
}


DEFUN(cli_radius_server_remove_retries,
        radius_server_remove_retries_cmd,
        "no radius-server retries <0-5>",
        NO_STR
        "Radius server configuration\n"
        "Set the number of retries\n"
        "Set the range from 0 to 5. (Default: 1)\n")
{
    return radius_server_remove_retries(argv[0]);
}

/* Set RADIUS server 'timeout' to the all hosts.
 * On failure, returns CMD_OVSDB_FAILURE.
 */
static int
radius_server_set_timeout(const char *timeout)
{
    int64_t time_out = atoi(timeout);
    const struct ovsrec_radius_server *row = NULL;
    enum ovsdb_idl_txn_status txn_status;
    struct ovsdb_idl_txn *status_txn = cli_do_config_start();

    if (status_txn == NULL)
    {
        VLOG_ERR(OVSDB_TXN_CREATE_ERROR);
        cli_do_config_abort(status_txn);
        return CMD_OVSDB_FAILURE;
    }

    row = ovsrec_radius_server_first(idl);
    if (!row)
    {
        vty_out(vty, "No radius servers configured%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_ROW_FETCH_ERROR);
        cli_do_config_abort(status_txn);
        return CMD_OVSDB_FAILURE;
    }

    OVSREC_RADIUS_SERVER_FOR_EACH(row, idl)
    {
        ovsrec_radius_server_set_timeout(row, &time_out, 1);
    }

    txn_status = cli_do_config_finish(status_txn);

    if (txn_status == TXN_SUCCESS || txn_status == TXN_UNCHANGED)
    {
        return CMD_SUCCESS;
    }
    else
    {
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }
}


DEFUN(cli_radius_server_configure_timeout,
        radius_server_configure_timeout_cmd,
        "radius-server timeout <1-60>",
        "Radius server configuration\n"
        "Set the transmission timeout interval\n"
        "Timeout interval 1 to 60 seconds. (Default: 5)\n")
{
    return radius_server_set_timeout(argv[0]);
}

/* Removes RADIUS server configured 'timeout' and sets to default value 5.
 * On failure, returns CMD_OVSDB_FAILURE.
 */
static int
radius_server_remove_timeout(const char *timeout_t)
{
    int64_t timeout1, time = atoi(timeout_t);

    const struct ovsrec_radius_server *tempRow = NULL;
    struct ovsdb_idl_txn *status_txn = cli_do_config_start();

    enum ovsdb_idl_txn_status txn_status;

    timeout1 = RADIUS_SERVER_DEFAULT_TIMEOUT;
    if (status_txn == NULL)
    {
        VLOG_ERR(OVSDB_TXN_CREATE_ERROR);
        cli_do_config_abort(status_txn);
        return CMD_OVSDB_FAILURE;
    }
    tempRow = ovsrec_radius_server_first(idl);
    if (*(tempRow->timeout) == time)
    {
        OVSREC_RADIUS_SERVER_FOR_EACH(tempRow, idl)
        {
            ovsrec_radius_server_set_timeout(tempRow, &timeout1, 1);
        }
    }
    else
    {
        vty_out(vty, "Mismatched timeout value%s", VTY_NEWLINE);
        cli_do_config_abort(status_txn);
        return CMD_SUCCESS;
    }

    txn_status = cli_do_config_finish(status_txn);

    if (txn_status == TXN_SUCCESS || txn_status == TXN_UNCHANGED)
    {
        return CMD_SUCCESS;
    }
    else
    {
        VLOG_ERR
            ("Commiting transaction to DB failed in function=%s, line=%d \n",
                    __func__, __LINE__);
        return CMD_OVSDB_FAILURE;
    }
}

DEFUN(cli_radius_server_remove_timeout,
        radius_server_remove_timeout_cmd,
        "no radius-server timeout <1-60>",
        NO_STR
        "Radius server configuration\n"
        "Set the transmission timeout interval\n"
        "Timeout interval 1 to 60 seconds. (Default: 5)\n")
{
    return radius_server_remove_timeout(argv[0]);
}

/* Set RADIUS server authentication 'port' for the host 'ipv4'.
 * On failure, returns CMD_OVSDB_FAILURE.
 */
static int
radius_server_set_auth_port(const char *ipv4, const char *port)
{
    int64_t udp_port = atoi(port);
    int ret = 0;
    const struct ovsrec_radius_server *row = NULL;
    enum ovsdb_idl_txn_status txn_status;
    struct ovsdb_idl_txn *status_txn = NULL;

    ret = radius_server_add_host(ipv4);
    if (CMD_SUCCESS != ret)
    {
        return ret;
    }

    status_txn = cli_do_config_start();
    if (status_txn == NULL)
    {
        VLOG_ERR(OVSDB_TXN_CREATE_ERROR);
        cli_do_config_abort(status_txn);
        return CMD_OVSDB_FAILURE;
    }

    OVSREC_RADIUS_SERVER_FOR_EACH(row, idl)
    {
        if (!strcmp(row->ip_address, ipv4))
        {
            ovsrec_radius_server_set_udp_port(row, &udp_port, 1);
        }
    }

    txn_status = cli_do_config_finish(status_txn);

    if (txn_status == TXN_SUCCESS || txn_status == TXN_UNCHANGED)
    {
        return CMD_SUCCESS;
    }
    else
    {
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }
}

DEFUN(cli_radius_server_set_auth_port,
        radius_server_set_auth_port_cmd,
        "radius-server host A.B.C.D auth-port <0-65535>",
        "Radius server configuration\n"
        "Host IP address\n"
        "Radius server IPv4 address\n"
        "Set authentication port\n"
        "UDP port range is 0 to 65535. (Default: 1812)\n")
{
    return radius_server_set_auth_port(argv[0], argv[1]);
}

/* Shows RADIUS server configuration information.
 * If RADIUS server configured then display the configured information.
 */
static int
show_radius_server_info()
{
    const struct ovsrec_radius_server *row = NULL;
    char *temp[64];
    int count = 0, temp_count = 0;

    row = ovsrec_radius_server_first(idl);
    if (row == NULL)
    {
        vty_out(vty, "No Radius Servers configured%s", VTY_NEWLINE);
        return CMD_SUCCESS;
    }

    OVSREC_RADIUS_SERVER_FOR_EACH(row, idl)
    {
      /* Array buff max size is 60, since it should accomodate a string
       * in below format, where IP address max lenght is 15, port max
       * length is 5, passkey/shared secret max length is 32, retries
       * max length is 1 and timeout max length is 2.
       * {"<ipaddress>:<port> <passkey> <retries> <timeout> "}
       */
      char buff[60]= {0};

      sprintf(buff, "%s:%ld %s %ld %ld ", row->ip_address, *(row->udp_port), \
                             row->passkey, *(row->retries), *(row->timeout));
      temp[row->priority - 1] = (char *)malloc(strlen(buff));
      strncpy(temp[row->priority - 1], buff, strlen(buff));
      temp_count += 1;
    }

    vty_out(vty, "***** Radius Server information ******%s", VTY_NEWLINE);
    while( temp_count-- )
    {
        vty_out(vty, "Radius-server:%d%s", count + 1, VTY_NEWLINE);
        vty_out(vty, " Host IP address\t: %s%s",strtok(temp[count], ":"), VTY_NEWLINE);
        vty_out(vty, " Auth port\t\t: %s%s", strtok(NULL, " "), VTY_NEWLINE);
        vty_out(vty, " Shared secret\t\t: %s%s", strtok(NULL, " "), VTY_NEWLINE);
        vty_out(vty, " Retries\t\t: %s%s", strtok(NULL, " "), VTY_NEWLINE);
        vty_out(vty, " Timeout\t\t: %s%s", strtok(NULL, " "), VTY_NEWLINE);
        free(temp[count]);
        count++;
    }

    return CMD_SUCCESS;
}

/*================================================================================================*/
/* TACACS+ server name validation functions */
static const bool
tacacs_server_name_has_all_digits(const char *server_name)
{
    while (*server_name) {
           if (!ispunct(*server_name) && !isdigit(*server_name)) {
               return false;
           }
           server_name++;
    }
    return true;
}

static const bool
is_valid_ipv4_address(const char *server_ipv4_address)
{
    struct sockaddr_in sa;

    int result = inet_pton(AF_INET, server_ipv4_address, &(sa.sin_addr));

    if (result <= 0)
       return false;

    /* 0.0.0.0 - 0.255.255.255 are not valid host addresses */
    if (*server_ipv4_address == '0')
       return false;

    if(!IS_VALID_IPV4(htonl(sa.sin_addr.s_addr)))
        return false;

    return true;
}

static const bool
tacacs_is_valid_server_name(const char *server_name)
{
    if(!server_name) {
       return false;
    }

    if (tacacs_server_name_has_all_digits(server_name)) {
        return is_valid_ipv4_address(server_name);
    }

    return true;
}

const int
tacacs_server_sanitize_parameters(tacacs_server_params_t *server_params)
{
    /* Check server_name to see if it exceeds maximum number of characters */
    if (strlen(server_params->server_name) > MAX_CHARS_IN_TACACS_SERVER_NAME) {
        vty_out(vty, "Server name should be less than %d characters%s",
                     MAX_CHARS_IN_TACACS_SERVER_NAME, VTY_NEWLINE);
        return CMD_ERR_NOTHING_TODO;
    }

    /* Check the validity of server name */
    if (!tacacs_is_valid_server_name(server_params->server_name)) {
        vty_out(vty, "Invalid server name %s", VTY_NEWLINE);
        return CMD_ERR_NOTHING_TODO;
    }

    /* Check the validity of passkey */
    if (server_params->shared_key != NULL) {
        if (strlen(server_params->shared_key) > MAX_LENGTH_TACACS_PASSKEY) {
            vty_out(vty, "Length of passkey should be less than %d %s",
                         MAX_LENGTH_TACACS_PASSKEY, VTY_NEWLINE);
            return CMD_ERR_NOTHING_TODO;
        }
    }

   return CMD_SUCCESS;
}

static void
tacacs_server_replace_parameters(const struct ovsrec_tacacs_server *row,
        tacacs_server_params_t *server_params)
{
    if (server_params->timeout != NULL) {
        ovsrec_tacacs_server_set_timeout(row, atoi(server_params->timeout));
    }

    if (server_params->shared_key != NULL) {
        ovsrec_tacacs_server_set_passkey(row, server_params->shared_key);
    }

    if (server_params->auth_type != NULL) {
        ovsrec_tacacs_server_set_auth_type(row, server_params->auth_type);
    }
}

static void
tacacs_server_fetch_parameters(const struct ovsrec_system *ovs,
                               tacacs_server_params_t *server_params)
{
    /* Fetch global config values */
    if (server_params->auth_port == NULL)
    {
        server_params->auth_port = smap_get(&ovs->aaa, SYSTEM_AAA_TACACS_TCP_PORT);
    }

    if (server_params->timeout == NULL)
    {
        server_params->timeout = smap_get(&ovs->aaa, SYSTEM_AAA_TACACS_TIMEOUT);
    }

    if (server_params->shared_key == NULL)
    {
        server_params->shared_key =  smap_get(&ovs->aaa, SYSTEM_AAA_TACACS_PASSKEY);
    }

    if (server_params->auth_type == NULL)
    {
        server_params->auth_type = smap_get(&ovs->aaa, SYSTEM_AAA_TACACS_AUTH);
    }
}

static void
tacacs_server_add_parameters(const struct ovsrec_tacacs_server *row,
                             tacacs_server_params_t *server_params,
                             const struct ovsrec_aaa_server_group *group)
{
    ovsrec_tacacs_server_set_ip_address(row, server_params->server_name);
    ovsrec_tacacs_server_set_timeout(row, atoi(server_params->timeout));
    ovsrec_tacacs_server_set_passkey(row, server_params->shared_key);
    ovsrec_tacacs_server_set_tcp_port(row, atoi(server_params->auth_port));
    ovsrec_tacacs_server_set_default_priority(row, server_params->priority);
    ovsrec_tacacs_server_set_group_priority(row, TACACS_SERVER_GROUP_PRIORITY_DEFAULT);
    ovsrec_tacacs_server_set_group(row, group);
    ovsrec_tacacs_server_set_auth_type(row, server_params->auth_type);
}

/* Add or remove a TACACS+ server */
static int
configure_tacacs_server_host(tacacs_server_params_t *server_params)
{
    const struct ovsrec_tacacs_server *row = NULL;
    const struct ovsrec_tacacs_server **tacacs_info = NULL;
    const struct ovsrec_system *ovs = NULL;
    struct ovsdb_idl_txn *status_txn = NULL;

    int retVal = tacacs_server_sanitize_parameters(server_params);
    if (retVal != CMD_SUCCESS) {
        return retVal;
    }

    /* Fetch the System row */
    ovs = ovsrec_system_first(idl);
    if (ovs == NULL) {
        ABORT_DB_TXN(status_txn, "Unable to fetch System table row");
    }

    /* Fetch global default tacacs-server parameter if not provided */
    tacacs_server_fetch_parameters(ovs, server_params);

    /* Start of transaction */
    START_DB_TXN(status_txn);

    /* See if specified TACACS+ server already exists */
    row = get_tacacs_server_by_name_port(server_params->server_name, atoi(server_params->auth_port));
    if (row == NULL) {
        if (server_params->no_form) {
            /* Nothing to delete */
            vty_out(vty, "This server does not exist%s", VTY_NEWLINE);
        }
        else {
            /* Check if maximum allowed TACACS+ servers are already configured */
            if (ovs->n_tacacs_servers >= MAX_TACACS_SERVERS) {
                vty_out(vty, "Exceeded maximum TACACS+ servers support%s", VTY_NEWLINE);
                END_DB_TXN(status_txn);
            }

            row = ovsrec_tacacs_server_insert(status_txn);
            if (NULL == row) {
                VLOG_ERR("Could not insert a row into the TACACS+ Server Table\n");
                ERRONEOUS_DB_TXN(status_txn, "Could not insert a row into the TACACS Server Table");
            }
            else {
                VLOG_DBG("Inserted a row into the TACACS+ Server Table successfully\n");
                const struct ovsrec_aaa_server_group *default_group = NULL;
                const struct ovsrec_tacacs_server *row_iter = NULL;
                int64_t priority = 0;
                int iter = 0;
                default_group = get_row_by_server_group_name(SYSTEM_AAA_TACACS_PLUS);
                if (!default_group)
                {
                    VLOG_ERR("TACACS+ Default Server Group not configured!\n");
                    ERRONEOUS_DB_TXN(status_txn, "TACACS+ Default Server Group not configured!");
                }

                OVSREC_TACACS_SERVER_FOR_EACH(row_iter, idl) {
                    if ((default_group == row_iter->group) &&
                        (row_iter->default_priority >= priority))
                    {
                        priority = row_iter->default_priority;
                    }
                }
                ++priority;
                server_params->priority = priority;
                tacacs_server_add_parameters(row, server_params, default_group);

                /* Update System table */
                tacacs_info = xmalloc(sizeof *ovs->tacacs_servers * (ovs->n_tacacs_servers + 1));
                for (iter = 0; iter < ovs->n_tacacs_servers; iter++) {
                    tacacs_info[iter] = ovs->tacacs_servers[iter];
                }
                tacacs_info[ovs->n_tacacs_servers] = row;
                ovsrec_system_set_tacacs_servers(ovs,
                        (struct ovsrec_tacacs_server **) tacacs_info,
                        ovs->n_tacacs_servers + 1);
                free(tacacs_info);
            }
        }
    }
    else {
        if (server_params->no_form) {
            VLOG_DBG("Deleting a row from the Tacacs Server table\n");
            int iter = 0;
            int count = 0;

            /* Delete the server */
            ovsrec_tacacs_server_delete(row);

            /* Update System table */
            tacacs_info = xmalloc(sizeof *ovs->tacacs_servers * ovs->n_tacacs_servers);
            for (iter = 0; iter < ovs->n_tacacs_servers; iter++) {
                if (ovs->tacacs_servers[iter] != row) {
                    tacacs_info[count++] = ovs->tacacs_servers[iter];
                }
            }
            ovsrec_system_set_tacacs_servers(ovs,
                        (struct ovsrec_tacacs_server **) tacacs_info,
                        count);
            free(tacacs_info);
        } else {
            /* Update existing server */
            tacacs_server_replace_parameters(row, server_params);
        }
    }

    /* End of transaction. */
    END_DB_TXN(status_txn);
}

DEFUN(cli_show_radius_server,
        show_radius_server_cmd,
        "show radius-server", SHOW_STR "Show radius server configuration\n")
{
    return show_radius_server_info();
}

static void
show_global_tacacs_config(const struct ovsrec_system *ovs)
{
    const char *passkey = NULL;
    const char *auth_type = NULL;
    int64_t tcp_port = 0;
    int64_t timeout = 0;

    /* Fetch global values */
    passkey = smap_get(&ovs->aaa, SYSTEM_AAA_TACACS_PASSKEY);
    tcp_port = atoi(smap_get(&ovs->aaa, SYSTEM_AAA_TACACS_TCP_PORT));
    timeout = atoi(smap_get(&ovs->aaa,  SYSTEM_AAA_TACACS_TIMEOUT));
    auth_type = smap_get(&ovs->aaa, SYSTEM_AAA_TACACS_AUTH);

    vty_out(vty, "%s******* Global TACACS+ Configuration ******* %s", VTY_NEWLINE, VTY_NEWLINE);
    vty_out(vty, "Shared-Secret: %s %s", passkey, VTY_NEWLINE);
    vty_out(vty, "Timeout: %ld %s", timeout, VTY_NEWLINE);
    vty_out(vty, "Auth-Port: %ld %s", tcp_port, VTY_NEWLINE);
    vty_out (vty, "Auth-Type: %s %s", auth_type, VTY_NEWLINE);
    vty_out(vty, "Number of Servers: %zd %s%s", ovs->n_tacacs_servers, VTY_NEWLINE, VTY_NEWLINE);
}


static void
show_tacacs_server_entry(const struct ovsrec_tacacs_server *row)
{
    vty_out(vty, "%-25s: %s%s", "Server-Name", row->ip_address, VTY_NEWLINE);
    vty_out(vty, "%-25s: %ld%s", "Auth-Port", row->tcp_port, VTY_NEWLINE);
    vty_out(vty, "%-25s: %s%s", "Shared-Secret", row->passkey, VTY_NEWLINE);
    vty_out(vty, "%-25s: %ld%s", "Timeout", row->timeout, VTY_NEWLINE);
    vty_out(vty, "%-25s: %s%s", "Auth-Type", row->auth_type, VTY_NEWLINE);
    if (VTYSH_STR_EQ(row->group->group_name, SYSTEM_AAA_TACACS_PLUS))
    {
        vty_out(vty, "%-25s: %s (default)%s", "Server-Group", row->group->group_name, VTY_NEWLINE);
        vty_out(vty, "%-25s: %ld%s", "Default-Priority", row->default_priority, VTY_NEWLINE);
    }
    else
    {
        vty_out(vty, "%-25s: %s%s", "Server-Group", row->group->group_name, VTY_NEWLINE);
        vty_out(vty, "%-25s: %ld%s", "Group-Priority", row->group_priority, VTY_NEWLINE);
    }
    vty_out(vty, "%s", VTY_NEWLINE);
}

/* Display details for each TACACS+ server */
static void
show_detailed_tacacs_server_data()
{
    int count = 0;
    bool sort_by_default_priority = false;
    int idx = 0;
    const struct ovsrec_aaa_server_group *group_row = NULL;
    const struct ovsrec_aaa_server_group *default_group = NULL;
    const struct ovsrec_tacacs_server *row = NULL;
    struct shash sorted_tacacs_servers;
    const struct shash_node **nodes;

    if (!ovsrec_tacacs_server_first(idl))
    {
        return;
    }

    shash_init(&sorted_tacacs_servers);
    OVSREC_TACACS_SERVER_FOR_EACH(row, idl)
    {
        shash_add(&sorted_tacacs_servers, row->ip_address, (void *)row);
    }
    nodes = sort_tacacs_server(&sorted_tacacs_servers, sort_by_default_priority);

    if (nodes == NULL)
    {
       shash_destroy(&sorted_tacacs_servers);
       return;
    }

    count = shash_count(&sorted_tacacs_servers);
    vty_out(vty, "****** TACACS+ Server Information ******%s", VTY_NEWLINE);

    OVSREC_AAA_SERVER_GROUP_FOR_EACH(group_row, idl)
    {
        if (VTYSH_STR_EQ(group_row->group_name, SYSTEM_AAA_TACACS_PLUS)
            || VTYSH_STR_EQ(group_row->group_name, SYSTEM_AAA_RADIUS)
            || VTYSH_STR_EQ(group_row->group_name, SYSTEM_AAA_LOCAL))
        {
            continue;
        }

        for(idx = 0; idx < count; idx++)
        {
            row = (const struct ovsrec_tacacs_server *)nodes[idx]->data;
            if (group_row == row->group)
            {
                show_tacacs_server_entry(row);
            }
        }
    }

    sort_by_default_priority = true;
    free(nodes);
    nodes = NULL;
    nodes = sort_tacacs_server(&sorted_tacacs_servers, sort_by_default_priority);
    default_group = get_row_by_server_group_name(SYSTEM_AAA_TACACS_PLUS);

    for(idx = 0; idx < count; idx++)
    {
        row = (const struct ovsrec_tacacs_server *)nodes[idx]->data;
        if (row->group == default_group)
        {
            show_tacacs_server_entry(row);
        }
    }

    shash_destroy(&sorted_tacacs_servers);
    free(nodes);
}

/* Summarized details for TACACS+ servers */
static void
show_summarized_tacacs_server_data()
{
    const struct ovsrec_tacacs_server *row = NULL;
    char row_separator[AAA_TABLE_WIDTH + 1] = {};
    int count = 0;
    int idx = 0;
    bool sort_by_default_priority = true;
    struct shash sorted_tacacs_servers;
    const struct shash_node **nodes;

    /* Create row seperator string*/
    for(idx = 0; idx < AAA_TABLE_WIDTH; idx++)
        row_separator[idx] = '-';
    row_separator[AAA_TABLE_WIDTH] = '\0';

    /* Sort tacacs server by default_priority*/
    shash_init(&sorted_tacacs_servers);
    OVSREC_TACACS_SERVER_FOR_EACH(row, idl)
    {
        shash_add(&sorted_tacacs_servers, row->ip_address, (void *)row);
    }
    nodes = sort_tacacs_server(&sorted_tacacs_servers, sort_by_default_priority);

    if (nodes == NULL)
    {
       shash_destroy(&sorted_tacacs_servers);
       return;
    }

    count = shash_count(&sorted_tacacs_servers);
    vty_out(vty, "%s%s", row_separator, VTY_NEWLINE);
    vty_out(vty, "%-45s | %-5s%s", "SERVER NAME", "PORT", VTY_NEWLINE);
    vty_out(vty, "%s%s", row_separator, VTY_NEWLINE);

    for(idx = 0; idx < count; idx++)
    {
        row = (const struct ovsrec_tacacs_server *)nodes[idx]->data;
        vty_out(vty,"%-45s | %-5ld%s", row->ip_address, row->tcp_port, VTY_NEWLINE);
    }
    shash_destroy(&sorted_tacacs_servers);
    free(nodes);
}

static int
show_tacacs_server_info(bool showDetails)
{
    const struct ovsrec_tacacs_server *row = NULL;
    const struct ovsrec_system *ovs = NULL;

    /* Fetch the system row */
    ovs = ovsrec_system_first(idl);
    if (ovs == NULL) {
        vty_out(vty, "Command failed%s", VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    /* display global config */
    show_global_tacacs_config(ovs);

    row = ovsrec_tacacs_server_first(idl);
    if (row == NULL) {
        vty_out(vty, "No TACACS+ Servers configured%s", VTY_NEWLINE);
        return CMD_SUCCESS;
    }

    if (showDetails) {
        show_detailed_tacacs_server_data();
    } else {
        show_summarized_tacacs_server_data();
    }

    return CMD_SUCCESS;
}


DEFUN(cli_show_tacacs_server,
      show_tacacs_server_cmd,
      "show tacacs-server {detail}",
      SHOW_STR
      SHOW_TACACS_SERVER_HELP_STR
      SHOW_DETAILS_HELP_STR)
{
    bool detail = false;

    if (argv[0] != NULL && !strcmp(argv[0], "detail"))
    {
        detail = true;
    }

   return show_tacacs_server_info(detail);
}


/* CLI to add tacacs-sever */
DEFUN (cli_tacacs_server_host,
       tacacs_server_host_cmd,
       "tacacs-server host WORD {port <1-65535> | timeout <1-60> | key WORD | auth-type (pap | chap)}",
       TACACS_SERVER_HELP_STR
       TACACS_SERVER_HOST_HELP_STR
       TACACS_SERVER_NAME_HELP_STR
       AUTH_PORT_HELP_STR
       AUTH_PORT_RANGE_HELP_STR
       TIMEOUT_HELP_STR
       TIMEOUT_RANGE_HELP_STR
       SHARED_KEY_HELP_STR
       SHARED_KEY_VAL_HELP_STR
       AAA_AUTH_TYPE_HELP_STR
       AUTH_TYPE_PAP_HELP_STR
       AUTH_TYPE_CHAP_HELP_STR)
{
    tacacs_server_params_t tacacs_server_params = {0};

    if (vty_flags & CMD_FLAG_NO_CMD)
    {
        tacacs_server_params.no_form = true;
        tacacs_server_params.server_name = argv[0];
        tacacs_server_params.auth_port = argv[1];
    }
    else
    {
        tacacs_server_params.server_name = argv[0];
        tacacs_server_params.auth_port = argv[1];
        tacacs_server_params.timeout = argv[2];
        tacacs_server_params.shared_key = argv[3];
        tacacs_server_params.auth_type = argv[4];
        tacacs_server_params.no_form = false;
    }

    return configure_tacacs_server_host(&tacacs_server_params);
}

/* CLI to remove tacacs-sever */
DEFUN_NO_FORM (cli_tacacs_server_host,
       tacacs_server_host_cmd,
       "tacacs-server host WORD {port <1-65535>}",
       TACACS_SERVER_HELP_STR
       TACACS_SERVER_HOST_HELP_STR
       TACACS_SERVER_NAME_HELP_STR
       AUTH_PORT_HELP_STR
       AUTH_PORT_RANGE_HELP_STR);

/* Shows auto provisioning status.*/
static int
show_auto_provisioning()
{
    const struct ovsrec_system *row = NULL;

    row = ovsrec_system_first(idl);

    if (!row)
    {
        VLOG_ERR(OVSDB_ROW_FETCH_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    if (smap_get(&row->auto_provisioning_status, "performed") != NULL)
    {
        if (!strcmp
                (smap_get(&row->auto_provisioning_status, "performed"), "True"))
        {
            vty_out(vty, " Performed : %s%s", "Yes", VTY_NEWLINE);
            vty_out(vty, " URL       : %s%s",
                    smap_get(&row->auto_provisioning_status, "url"),
                    VTY_NEWLINE);
        }
        else
        {
            vty_out(vty, " Performed : %s%s", "No", VTY_NEWLINE);
        }
    }

    return CMD_SUCCESS;
}

/* CLI to show auto provisioning status */
DEFUN(cli_show_auto_provisioning,
        show_auto_provisioning_cmd,
        "show autoprovisioning", SHOW_STR "Show auto provisioning status\n")
{
    return show_auto_provisioning();
}

/* Shows ssh authentication method.*/
static int
show_ssh_auth_method()
{
    const struct ovsrec_system *row = NULL;

    row = ovsrec_system_first(idl);

    if (!row)
    {
        VLOG_ERR(OVSDB_ROW_FETCH_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    if (!strcmp
            (smap_get(&row->aaa, SSH_PUBLICKEY_AUTHENTICATION_ENABLE),
                       SSH_AUTH_ENABLE))
    {
        vty_out(vty, " SSH publickey authentication : %s%s", "Enabled",
                VTY_NEWLINE);
    }
    else
    {
        vty_out(vty, " SSH publickey authentication : %s%s", "Disabled",
                VTY_NEWLINE);
    }

    if (!strcmp
            (smap_get(&row->aaa, SSH_PASSWORD_AUTHENTICATION_ENABLE),
                       SSH_AUTH_ENABLE))
    {
        vty_out(vty, " SSH password authentication  : %s%s", "Enabled",
                VTY_NEWLINE);
    }
    else
    {
        vty_out(vty, " SSH password authentication  : %s%s", "Disabled",
                VTY_NEWLINE);
    }

    return CMD_SUCCESS;
}

/* CLI to show authentication mechanism configured in DB */
DEFUN(cli_show_ssh_auth_method,
        show_ssh_auth_method_cmd,
        "show ssh authentication-method",
        SHOW_STR "Show SSH configuration\n" "Show authentication method\n")
{
    return show_ssh_auth_method();
}

/* Set ssh public key aythentication status.*/
static int
set_ssh_publickey_auth(const char *status)
{
    const struct ovsrec_system *row = NULL;
    enum ovsdb_idl_txn_status txn_status;
    struct ovsdb_idl_txn *status_txn = cli_do_config_start();
    struct smap smap_aaa;

    if (status_txn == NULL)
    {
        VLOG_ERR(OVSDB_TXN_CREATE_ERROR);
        cli_do_config_abort(status_txn);
        return CMD_OVSDB_FAILURE;
    }

    row = ovsrec_system_first(idl);

    if (!row)
    {
        VLOG_ERR(OVSDB_ROW_FETCH_ERROR);
        cli_do_config_abort(status_txn);
        return CMD_OVSDB_FAILURE;
    }

    smap_clone(&smap_aaa, &row->aaa);

    if (strcmp(SSH_AUTH_ENABLE, status) == 0)
    {
        smap_replace(&smap_aaa, SSH_PUBLICKEY_AUTHENTICATION_ENABLE,
                      SSH_AUTH_ENABLE);
    }
    else if (strcmp(SSH_AUTH_DISABLE, status) == 0)
    {
        smap_replace(&smap_aaa, SSH_PUBLICKEY_AUTHENTICATION_ENABLE,
                      SSH_AUTH_DISABLE);
    }

    ovsrec_system_set_aaa(row, &smap_aaa);

    txn_status = cli_do_config_finish(status_txn);
    smap_destroy(&smap_aaa);

    if (txn_status == TXN_SUCCESS || txn_status == TXN_UNCHANGED)
    {
        return CMD_SUCCESS;
    }
    else
    {
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }
}

/* CLI to enable ssh public key authentication */
DEFUN(cli_set_ssh_publickey_auth,
        set_ssh_publickey_auth_cmd,
        "ssh public-key-authentication",
        "SSH authentication\n" "Enable publickey authentication method\n")
{
    return set_ssh_publickey_auth(SSH_AUTH_ENABLE);
}

/* CLI to disable ssh public key authentication */
DEFUN(cli_no_set_ssh_publickey_auth,
        no_set_ssh_publickey_auth_cmd,
        "no ssh public-key-authentication",
        NO_STR
        "SSH authentication\n" "Enable publickey authentication method\n")
{
    return set_ssh_publickey_auth(SSH_AUTH_DISABLE);
}

/* Set ssh password authentication.*/
static int
set_ssh_password_auth(const char *status)
{
    const struct ovsrec_system *row = NULL;
    enum ovsdb_idl_txn_status txn_status;
    struct ovsdb_idl_txn *status_txn = cli_do_config_start();
    struct smap smap_aaa;

    if (status_txn == NULL)
    {
        VLOG_ERR(OVSDB_TXN_CREATE_ERROR);
        cli_do_config_abort(status_txn);
        return CMD_OVSDB_FAILURE;
    }

    row = ovsrec_system_first(idl);

    if (!row)
    {
        VLOG_ERR(OVSDB_ROW_FETCH_ERROR);
        cli_do_config_abort(status_txn);
        return CMD_OVSDB_FAILURE;
    }

    smap_clone(&smap_aaa, &row->aaa);

    if (strcmp(SSH_AUTH_ENABLE, status) == 0)
    {
        smap_replace(&smap_aaa, SSH_PASSWORD_AUTHENTICATION_ENABLE,
                      SSH_AUTH_ENABLE);
    }
    else if (strcmp(SSH_AUTH_DISABLE, status) == 0)
    {
        smap_replace(&smap_aaa, SSH_PASSWORD_AUTHENTICATION_ENABLE,
                      SSH_AUTH_DISABLE);
    }

    ovsrec_system_set_aaa(row, &smap_aaa);

    txn_status = cli_do_config_finish(status_txn);
    smap_destroy(&smap_aaa);

    if (txn_status == TXN_SUCCESS || txn_status == TXN_UNCHANGED)
    {
        return CMD_SUCCESS;
    }
    else
    {
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }
}

/* CLI to enable ssh password athentication */
DEFUN(cli_set_ssh_password_auth,
        set_ssh_password_auth_cmd,
        "ssh password-authentication",
        "SSH authentication\n" "Enable password authentication method\n")
{
    return set_ssh_password_auth(SSH_AUTH_ENABLE);
}

/* CLI to disable ssh password athentication */
DEFUN(cli_no_set_ssh_password_auth,
        no_set_ssh_password_auth_cmd,
        "no ssh password-authentication",
        NO_STR "SSH authentication\n" "Enable password authentication method\n")
{
    return set_ssh_password_auth(SSH_AUTH_DISABLE);
}

/*******************************************************************
 * @func        : aaa_ovsdb_init
 * @detail      : Add aaa related table & columns to ops-cli
 *                idl cache
 *******************************************************************/
static void
aaa_ovsdb_init(void)
{
    /* Add AAA columns. */
    ovsdb_idl_add_column(idl, &ovsrec_system_col_aaa);
    ovsdb_idl_add_table(idl, &ovsrec_table_aaa_server_group);
    ovsdb_idl_add_column(idl, &ovsrec_aaa_server_group_col_group_type);
    ovsdb_idl_add_column(idl, &ovsrec_aaa_server_group_col_group_name);
    ovsdb_idl_add_column(idl, &ovsrec_aaa_server_group_col_is_static);
    ovsdb_idl_add_table(idl, &ovsrec_table_aaa_server_group_prio);
    ovsdb_idl_add_column(idl, &ovsrec_aaa_server_group_prio_col_session_type);
    ovsdb_idl_add_column(idl, &ovsrec_aaa_server_group_prio_col_authentication_group_prios);

    /* Add Auto Provision Column. */
    ovsdb_idl_add_column(idl, &ovsrec_system_col_auto_provisioning_status);

    /* Add radius-server columns. */
    ovsdb_idl_add_column(idl, &ovsrec_system_col_radius_servers);
    ovsdb_idl_add_table(idl, &ovsrec_table_radius_server);
    ovsdb_idl_add_column(idl, &ovsrec_radius_server_col_retries);
    ovsdb_idl_add_column(idl, &ovsrec_radius_server_col_ip_address);
    ovsdb_idl_add_column(idl, &ovsrec_radius_server_col_udp_port);
    ovsdb_idl_add_column(idl, &ovsrec_radius_server_col_timeout);
    ovsdb_idl_add_column(idl, &ovsrec_radius_server_col_passkey);
    ovsdb_idl_add_column(idl, &ovsrec_radius_server_col_priority);

    /* Add tacacs-server columns. */
    ovsdb_idl_add_column(idl, &ovsrec_system_col_tacacs_servers);
    ovsdb_idl_add_table(idl, &ovsrec_table_tacacs_server);
    ovsdb_idl_add_column(idl, &ovsrec_tacacs_server_col_ip_address);
    ovsdb_idl_add_column(idl, &ovsrec_tacacs_server_col_tcp_port);
    ovsdb_idl_add_column(idl, &ovsrec_tacacs_server_col_timeout);
    ovsdb_idl_add_column(idl, &ovsrec_tacacs_server_col_passkey);
    ovsdb_idl_add_column(idl, &ovsrec_tacacs_server_col_auth_type);
    ovsdb_idl_add_column(idl, &ovsrec_tacacs_server_col_default_priority);
    ovsdb_idl_add_column(idl, &ovsrec_tacacs_server_col_group_priority);
    ovsdb_idl_add_column(idl, &ovsrec_tacacs_server_col_group);

    return;
}

/* Initialize AAA related cli node.
 */
void
cli_pre_init(void)
{
    aaa_ovsdb_init();
    return;
}

/* Install  AAA related vty command elements. */
void
cli_post_init(void)
{
    vtysh_ret_val retval = e_vtysh_error;

    /* Install default VTY commands to new nodes.  */
    install_default (AAA_SERVER_GROUP_NODE);
    install_element(ENABLE_NODE, &aaa_show_aaa_authenctication_cmd);
    install_element(CONFIG_NODE, &aaa_set_global_status_cmd);
    install_element(CONFIG_NODE, &no_aaa_set_global_status_cmd);
    install_element(CONFIG_NODE, &aaa_set_authentication_cmd);
    install_element(CONFIG_NODE, &no_aaa_set_authentication_cmd);
    install_element(CONFIG_NODE, &aaa_set_radius_authentication_cmd);
    install_element(CONFIG_NODE, &aaa_remove_fallback_cmd);
    install_element(CONFIG_NODE, &aaa_no_remove_fallback_cmd);
    install_element(CONFIG_NODE, &aaa_create_tacacs_server_group_cmd);
    install_element(CONFIG_NODE, &no_aaa_create_tacacs_server_group_cmd);
    install_element(AAA_SERVER_GROUP_NODE, &aaa_group_add_server_cmd);
    install_element(AAA_SERVER_GROUP_NODE, &no_aaa_group_add_server_cmd);
    install_element(CONFIG_NODE, &tacacs_server_set_passkey_cmd);
    install_element(CONFIG_NODE, &tacacs_server_set_port_cmd);
    install_element(CONFIG_NODE, &tacacs_server_set_timeout_cmd);
    install_element(CONFIG_NODE, &tacacs_server_set_auth_type_cmd);
    install_element(CONFIG_NODE, &no_tacacs_server_set_passkey_cmd);
    install_element(CONFIG_NODE, &no_tacacs_server_set_port_cmd);
    install_element(CONFIG_NODE, &no_tacacs_server_set_timeout_cmd);
    install_element(CONFIG_NODE, &no_tacacs_server_set_auth_type_cmd);
    install_element(CONFIG_NODE, &tacacs_server_host_cmd);
    install_element(CONFIG_NODE, &no_tacacs_server_host_cmd);
    install_element(CONFIG_NODE, &radius_server_add_host_cmd);
    install_element(CONFIG_NODE, &radius_server_remove_host_cmd);
    install_element(CONFIG_NODE, &radius_server_remove_passkey_cmd);
    install_element(CONFIG_NODE, &radius_server_remove_auth_port_cmd);
    install_element(CONFIG_NODE, &radius_server_remove_retries_cmd);
    install_element(CONFIG_NODE, &radius_server_remove_timeout_cmd);
    install_element(CONFIG_NODE, &radius_server_passkey_host_cmd);
    install_element(CONFIG_NODE, &radius_server_retries_cmd);
    install_element(CONFIG_NODE, &radius_server_configure_timeout_cmd);
    install_element(CONFIG_NODE, &radius_server_set_auth_port_cmd);
    install_element(ENABLE_NODE, &show_radius_server_cmd);
    install_element(ENABLE_NODE, &show_tacacs_server_cmd);
    install_element(ENABLE_NODE, &show_aaa_server_groups_cmd);
    install_element(ENABLE_NODE, &show_auto_provisioning_cmd);
    install_element(ENABLE_NODE, &show_ssh_auth_method_cmd);
    install_element(CONFIG_NODE, &set_ssh_publickey_auth_cmd);
    install_element(CONFIG_NODE, &no_set_ssh_publickey_auth_cmd);
    install_element(CONFIG_NODE, &set_ssh_password_auth_cmd);
    install_element(CONFIG_NODE, &no_set_ssh_password_auth_cmd);

    /* Installing running config sub-context with global config context */
    retval = install_show_run_config_subcontext(e_vtysh_config_context,
                                                e_vtysh_config_context_aaa,
                                                &vtysh_config_context_aaa_clientcallback,
                                                NULL, NULL);
    if(e_vtysh_ok != retval)
    {
        vtysh_ovsdb_config_logmsg(VTYSH_OVSDB_CONFIG_ERR,
                              "config context unable to add aaa client callback");
        assert(0);
    }
    return;
}
