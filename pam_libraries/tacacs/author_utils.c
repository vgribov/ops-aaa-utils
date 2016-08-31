/*
 * Copyright (C) 2016 Hewlett Packard Enterprise Development LP.
 * Copyright (C) 2010, Pawel Krawczyk <pawel.krawczyk@hush.com> and
 * Jeroen Nijhof <jeroen@jeroennijhof.nl>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program - see the file COPYING.
 *
 * File: author_utils.c
 * Purpose: Sends authorization request to the configured server.
 *          Obtains privilege level from the configured server.
 *
 */

#include <stdbool.h>
#include "libtac.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(author_utils);

/*
 * Wrapper function to receive TACACS authorization parameters from
 * TACC client/CLI and sends authorization request to the configured
 * server.
 * Returns: EXIT_OK         0  Authorized
 *          EXIT_FAIL       1  Authorization was denied
 *          EXIT_ADDR_ERR   2  Error when resolving TACACS server address
 *          EXIT_CONN_ERR   3  Connection to TACACS server failed
 *          EXIT_SEND_ERR   4  Error when sending authorization request
 */

int tac_cmd_author(const char *tac_server_name, const char *tac_secret,
                   const char *user, char * tty, char *remote_addr,
                   char *service, char *protocol, char *command,
                   int timeout, bool quiet, const char *source_ip,
                   const char *src_namespace, const char *dst_namespace ) {
    int ret;
    int tac_fd;
    int send_status;
    int status_code;
    struct areply arep;
    struct addrinfo *tac_server;
    struct addrinfo hints;
    struct tac_attrib *attr = NULL;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    /* Get addr_info structure for tac_server_name */
    if ((ret = getaddrinfo(tac_server_name, "tacacs", &hints, &tac_server)) != 0) {
        LOG(quiet, VLL_ERR, "error: resolving name %s: %s", tac_server_name,
            gai_strerror(ret))
        return EXIT_ADDR_ERR;
    }

    /* Set TACACS attributes */
    if (command != NULL) {
        tac_add_attrib(&attr, "cmd", command);
    }

    if (protocol != NULL) {
        tac_add_attrib(&attr, "protocol", protocol);
    }

    tac_add_attrib(&attr, "service", service);

    /* TACACS connection to tac_server */
    tac_fd = tac_connect_single(tac_server, tac_secret, NULL, timeout);

    if (tac_fd < 0) {
        char ip[tac_server->ai_addrlen];
        unsigned short port;
        if (get_ip_port_tuple(tac_server->ai_addr,
                               ip, &port, sizeof(ip), quiet) != NULL) {
            LOG(quiet, VLL_ERR, "Error connecting to TACACS+ server %s:%hu:"
                                 "%m\n",ip, port)
        } else {
            LOG(quiet, VLL_ERR, "Error connecting to TACACS+ server: %m\n")
        }
        status_code = EXIT_CONN_ERR;
        goto CLEAN_UP;
    }

    /* TACACS authorization request to the connected server fd */
    send_status = tac_author_send(tac_fd, user, tty, remote_addr, attr);

    if (send_status < 0) {
        LOG(quiet, VLL_ERR, "Sending authorization request failed\n");
        status_code = EXIT_SEND_ERR;
        goto CLEAN_UP;
    }

    /* Read TACACS server authorization response */
    tac_author_read(tac_fd, &arep);

    if (arep.status != AUTHOR_STATUS_PASS_ADD
        && arep.status != AUTHOR_STATUS_PASS_REPL) {
        LOG(quiet, VLL_ERR, "Authorization FAILED: %s\n", arep.msg);
        status_code = EXIT_FAIL;
    } else {
        LOG(quiet, VLL_INFO, "Authorization OK: %s\n", arep.msg);
        status_code = EXIT_OK;
    }

    CLEAN_UP:
        tac_free_attrib(&attr);
        freeaddrinfo(tac_server);
        return status_code;
}

/*
 * Returns IP in printable format and the port in host format.
 */
char * get_ip_port_tuple(struct sockaddr *sa, char *ip,
                         unsigned short *port, size_t maxlen,
                         bool quiet) {
    switch(sa->sa_family) {
        case AF_INET:
            inet_ntop(AF_INET, &(((struct sockaddr_in *)sa)->sin_addr),
                    ip, maxlen);
            *port = ntohs(((struct sockaddr_in*)sa)->sin_port);
            break;

        case AF_INET6:
            inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)sa)->sin6_addr),
                    ip, maxlen);
            *port = ntohs(((struct sockaddr_in6*)sa)->sin6_port);
            break;

        default:
            VLOG_DBG("Unknown address family %hu\n",sa->sa_family);
            return NULL;
    }
    return ip;
}
