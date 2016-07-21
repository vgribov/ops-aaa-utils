/* AAA CLI commands header file.
 *
 * Copyright (C) 2015-2016 Hewlett Packard Enterprise Development LP
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 *
 * File: aaa_vty.h
 *
 * Purpose:  To add declarations required for aaa_vty.c.
 */

#ifndef _AAA_VTY_H
#define _AAA_VTY_H


/* Structure defiitions */
typedef struct tacacs_server_params_s {
    bool no_form;           /* TRUE/FALSE */
    char *server_name;      /* FQDN or IP Address */
} tacacs_server_params_t;


/*
 * depending on the outcome of the db transaction, return
 * the appropriate value for the cli command execution.
*/
inline static int
config_finish_result (enum ovsdb_idl_txn_status status)
{
    if ((status == TXN_SUCCESS) || (status == TXN_UNCHANGED)) {
        fprintf(stdout, "txn success\n"); return CMD_SUCCESS;
    }
    return CMD_WARNING;
}

/********************** standard database txn operations **********************/

#define START_DB_TXN(txn)                                       \
    do {                                                        \
        txn = cli_do_config_start();                            \
        if (txn == NULL) {                                      \
            vty_out(vty, "ovsdb_idl_txn_create failed: %s: %d\n",   \
                    __FILE__, __LINE__);                            \
            cli_do_config_abort(txn);                               \
            return CMD_OVSDB_FAILURE;                               \
        }                                                           \
    } while (0)

#define END_DB_TXN(txn)                                   \
    do {                                                  \
        enum ovsdb_idl_txn_status status;                 \
        status = cli_do_config_finish(txn);               \
        return config_finish_result(status);                \
    } while (0)

#define ERRONEOUS_DB_TXN(txn, error_message)                        \
    do {                                                            \
        cli_do_config_abort(txn);                                   \
        vty_out(vty, "database transaction failed: %s: %d -- %s\n", \
                __FILE__, __LINE__, error_message);                 \
        return CMD_WARNING;                                         \
    } while (0)

/* used when NO error is detected but still need to terminate */
#define ABORT_DB_TXN(txn, message)                             \
    do {                                                       \
        cli_do_config_abort(txn);                                   \
        vty_out(vty, "database transaction aborted: %s: %d, %s\n",  \
                __FILE__, __LINE__, message);                       \
        return CMD_WARNING;                                         \
    } while (0)


/* Commonly used declarations */
#define SYSTEM_AAA_RADIUS               "radius"
#define SYSTEM_AAA_FALLBACK             "fallback"
#define SYSTEM_AAA_RADIUS_LOCAL         "local"
#define SYSTEM_AAA_RADIUS_AUTH          "radius_auth"
#define RADIUS_CHAP                     "chap"
#define RADIUS_PAP                      "pap"
#define OPS_TRUE_STR                        "true"
#define OPS_FALSE_STR                       "false"

#define MAX_RADIUS_SERVERS                    64
#define RADIUS_SERVER_DEFAULT_PASSKEY         "testing123-1"
#define RADIUS_SERVER_DEFAULT_PORT            1812
#define RADIUS_SERVER_DEFAULT_RETRIES         1
#define RADIUS_SERVER_DEFAULT_TIMEOUT         5

#define MAX_TACACS_SERVERS                    64
#define TACACS_SERVER_DEFAULT_PASSKEY         "testing123-1"
#define TACACS_SERVER_DEFAULT_PORT            1812
#define TACACS_SERVER_DEFAULT_TIMEOUT         5

#define AUTO_PROVISIONING_ENABLE              "enable"
#define AUTO_PROVISIONING_DISABLE             "disable"

#define SSH_AUTH_ENABLE                       "true"
#define SSH_AUTH_DISABLE                      "false"

#define SSH_PUBLICKEY_AUTHENTICATION_ENABLE "ssh_publickeyauthentication_enable"
#define SSH_PASSWORD_AUTHENTICATION_ENABLE  "ssh_passkeyauthentication_enable"

void cli_pre_init(void);
void cli_post_init(void);
#endif /* _AAA_VTY_H */
