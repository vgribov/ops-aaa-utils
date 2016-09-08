#!/usr/bin/env python
# Copyright (C) 2015-2016 Hewlett Packard Enterprise Development LP
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

import ovs.dirs
import ovs.daemon
import ovs.db.idl
import ovs.unixctl
import ovs.unixctl.server
import argparse
import ovs.vlog
import os

import vrf_utils

# Assign my_auth to default local config
my_auth = "passwd"

# Local variables to check if system is configured
system_initialized = 0

# Local varibale to check if default rows are updated
default_row_initialized = 0

# Ovs definition
idl = None

vlog = ovs.vlog.Vlog("ops_aaautilspamcfg")
def_db = 'unix:/var/run/openvswitch/db.sock'

# Schema path
ovs_schema = '/usr/share/openvswitch/vswitch.ovsschema'

# Program control
exiting = False
seqno = 0

PAM_ETC_CONFIG_DIR = "/etc/pam.d/"
RADIUS_CLIENT = "/etc/raddb/server"
SSHD_CONFIG = "/etc/ssh/sshd_config"

# OpenSSH banner files
# Post login banner
MOTD_FILE = "/etc/motd"
# Pre login banner
BANNER_FILE = "/etc/issue.net"

dispatch_list = []
SYSTEM_TABLE = "System"
SYSTEM_AAA_COLUMN = "aaa"
SYSTEM_OTHER_CONFIG = "other_config"
SYSTEM_RADIUS_SERVER_COLUMN = "radius_servers"
RADIUS_SERVER_TABLE = "Radius_Server"
SYSTEM_TACACS_SERVER_COLUMN = "tacacs_servers"
TACACS_SERVER_TABLE = "Tacacs_Server"
PORT_TABLE = "Port"
VRF_TABLE = "VRF"

SYSTEM_AUTO_PROVISIONING_STATUS_COLUMN = "auto_provisioning_status"

AAA_TACACS = "tacacs"
AAA_RADIUS = "radius"
AAA_RADIUS_AUTH = "radius_auth"
AAA_LOCAL = "local"
AAA_NONE = "none"
AAA_FAIL_THROUGH = "fail_through"
AAA_FAIL_THROUGH_ENABLED = False
AAA_TACACS_PLUS = "tacacs_plus"
AAA_TACACS_AUTH = "tacacs_auth"

AAA_TRUE_FLAG = "true"
AAA_FALSE_FLAG = "false"

AAA_SERVER_GROUP_TABLE = "AAA_Server_Group"
AAA_SERVER_GROUP_IS_STATIC = "is_static"
AAA_SERVER_GROUP_NAME = "group_name"
AAA_SERVER_GROUP_TYPE = "group_type"
AAA_DEFAULT_GROUP_STATIC = True

AAA_SERVER_GROUP_PRIO_TABLE = "AAA_Server_Group_Prio"
AAA_SERVER_GROUP_PRIO_SESSION_TYPE = "session_type"
AAA_AUTHENTICATION_GROUP_PRIOS = "authentication_group_prios"
AAA_AUTHORIZATION_GROUP_PRIOS = "authorization_group_prios"
AAA_SERVER_GROUP_PRIO_SESSION_TYPE_DEFAULT = "default"
PRIO_ZERO = 0

RADIUS_SERVER_IPADDRESS = "ip_address"
RADIUS_SERVER_PORT = "udp_port"
RADIUS_SERVER_PASSKEY = "passkey"
RADIUS_SERVER_TIMEOUT = "timeout"
RADIUS_SERVER_RETRIES = "retries"
RADIUS_SEREVR_PRIORITY = "priority"
RADIUS_PAP = "pap"
RADIUS_CHAP = "chap"

#TACACS+ Defaults
TACACS_SERVER_TCP_PORT_DEFAULT = "49"
TACACS_SERVER_PASSKEY_DEFAULT = "testing123-1"
TACACS_SERVER_TIMEOUT_DEFAULT = "5"

#TACACS+ Globals - from aaa column in System Table
GBL_TACACS_SERVER_PORT = "tacacs_tcp_port"
GBL_TACACS_SERVER_PASSKEY = "tacacs_passkey"
GBL_TACACS_SERVER_TIMEOUT = "tacacs_timeout"
GBL_TACACS_SERVER_AUTH_TYPE = "tacacs_auth"

#TACACS+ Server Columns
TACACS_SERVER_IPADDRESS = "ip_address"
TACACS_SERVER_PORT = "tcp_port"
TACACS_SERVER_PASSKEY = "passkey"
TACACS_SERVER_TIMEOUT = "timeout"
TACACS_SERVER_AUTH_TYPE = "auth_type"
TACACS_SERVER_GROUP = "group"
TACACS_SERVER_GROUP_PRIO = "group_priority"
TACACS_SERVER_DEFAULT_PRIO = "default_priority"

TACACS_PAP = "pap"
TACACS_CHAP = "chap"

PAM_TACACS_MODULE = "/usr/lib/security/libpam_tacplus.so"
PAM_LOCAL_MODULE = "pam_unix.so"

SSH_PASSKEY_AUTHENTICATION_ENABLE = "ssh_passkeyauthentication_enable"
SSH_PUBLICKEY_AUTHENTICATION_ENABLE = "ssh_publickeyauthentication_enable"
BANNER = "banner"
BANNER_EXEC = "banner_exec"
AUTH_KEY_ENABLE = "true"

SFTP_SERVER_CONFIG = "sftp_server_enable"

PERFORMED = "performed"
URL = "url"

global_tacacs_passkey = TACACS_SERVER_PASSKEY_DEFAULT
global_tacacs_timeout = TACACS_SERVER_TIMEOUT_DEFAULT
global_tacacs_auth = TACACS_PAP

tacacs_source_interface = None
radius_source_interface = None


#---------------- unixctl_exit --------------------------


def unixctl_exit(conn, unused_argv, unused_aux):
    global exiting

    exiting = True
    conn.reply(None)


#------------------ db_get_system_status() ----------------
def db_get_system_status(data):
    '''
    Check the configuration initialization completed
    (System:cur_cfg == true)
    '''
    for ovs_rec in data[SYSTEM_TABLE].rows.itervalues():
        if ovs_rec.cur_cfg:
            if ovs_rec.cur_cfg == 0:
                return False
            else:
                return True

    return False

#------------------ system_is_configured() ----------------
def system_is_configured():
    '''
    Check the OVS_DB if system initialization has completed.
    Initialization completed: return True
    else: return False
    '''

    global idl
    global system_initialized

    # Check the OVS-DB/File status to see if initialization has completed.
    if not db_get_system_status(idl.tables):
        # Delay a little before trying again
        os.sleep(1)
        return False

    system_initialized = 1
    return True


# ----------------- default_sshd_config -------------------
def default_sshd_config():
    '''Default modifications in sshd_config file
    to support auto provisioning'''
    with open(SSHD_CONFIG, 'r+') as fd:
        newdata = fd.read()

    newdata = newdata.replace("#PubkeyAuthentication yes",
                              "PubkeyAuthentication yes")
    newdata = newdata.replace("#PasswordAuthentication yes",
                              "PasswordAuthentication yes")
    newdata = newdata.replace("#PubkeyAuthentication no",
                              "PubkeyAuthentication no")
    newdata = newdata.replace("#PasswordAuthentication no",
                              "PasswordAuthentication no")
    newdata = newdata.replace("Subsystem	sftp	/usr/lib/openssh/sftp-server",
                              "#Subsystem	sftp	/usr/lib/openssh/sftp-server")

    with open(SSHD_CONFIG, 'w') as fd:
        fd.write(newdata)


# ----------------- add_default_row -----------------------
def add_default_row():
    '''
    System Table:
       Add default values to the radius and fallback columns
       by default radius is false and fallback is true
       Add default global config value for tacacs column
    AAA_Server_Group Table:
       Add default group local, tacacs+ and radius
    '''
    global idl
    global default_row_initialized

    data = {}
    prio_list_authentication = {}
    prio_list_authorization = {}
    auto_provisioning_data = {}

    # Default values for aaa column
    data[AAA_FAIL_THROUGH] = AAA_FALSE_FLAG
    data[AAA_RADIUS] = AAA_FALSE_FLAG
    data[AAA_RADIUS_AUTH] = RADIUS_PAP
    data[AAA_TACACS_AUTH] = TACACS_PAP
    data[SSH_PASSKEY_AUTHENTICATION_ENABLE] = AUTH_KEY_ENABLE
    data[SSH_PUBLICKEY_AUTHENTICATION_ENABLE] = AUTH_KEY_ENABLE
    # Default values for tacacs
    data[GBL_TACACS_SERVER_PASSKEY] = TACACS_SERVER_PASSKEY_DEFAULT
    data[GBL_TACACS_SERVER_TIMEOUT] = TACACS_SERVER_TIMEOUT_DEFAULT
    data[GBL_TACACS_SERVER_AUTH_TYPE] = TACACS_PAP

    # Default values for auto provisioning status column
    auto_provisioning_data[PERFORMED] = "False"
    auto_provisioning_data[URL] = ""

    # create the transaction
    txn = ovs.db.idl.Transaction(idl)
    for ovs_rec in idl.tables[SYSTEM_TABLE].rows.itervalues():
        break

    setattr(ovs_rec, SYSTEM_AAA_COLUMN, data)
    setattr(ovs_rec, SYSTEM_AUTO_PROVISIONING_STATUS_COLUMN,
            auto_provisioning_data)

    # create default server groups: local, tacacs+ and radius
    none_row = txn.insert(idl.tables[AAA_SERVER_GROUP_TABLE], new_uuid=None)
    setattr(none_row, AAA_SERVER_GROUP_IS_STATIC, AAA_DEFAULT_GROUP_STATIC)
    setattr(none_row, AAA_SERVER_GROUP_NAME, AAA_NONE)
    setattr(none_row, AAA_SERVER_GROUP_TYPE, AAA_NONE)

    local_row = txn.insert(idl.tables[AAA_SERVER_GROUP_TABLE], new_uuid=None)
    setattr(local_row, AAA_SERVER_GROUP_IS_STATIC, AAA_DEFAULT_GROUP_STATIC)
    setattr(local_row, AAA_SERVER_GROUP_NAME, AAA_LOCAL)
    setattr(local_row, AAA_SERVER_GROUP_TYPE, AAA_LOCAL)

    tacacs_row = txn.insert(idl.tables[AAA_SERVER_GROUP_TABLE], new_uuid=None)
    setattr(tacacs_row, AAA_SERVER_GROUP_IS_STATIC, AAA_DEFAULT_GROUP_STATIC)
    setattr(tacacs_row, AAA_SERVER_GROUP_NAME, AAA_TACACS_PLUS)
    setattr(tacacs_row, AAA_SERVER_GROUP_TYPE, AAA_TACACS_PLUS)

    radius_row = txn.insert(idl.tables[AAA_SERVER_GROUP_TABLE], new_uuid=None)
    setattr(radius_row, AAA_SERVER_GROUP_IS_STATIC, AAA_DEFAULT_GROUP_STATIC)
    setattr(radius_row, AAA_SERVER_GROUP_NAME, AAA_RADIUS)
    setattr(radius_row, AAA_SERVER_GROUP_TYPE, AAA_RADIUS)

    # create default AAA_Server_Group_Prio table session
    default_row = txn.insert(idl.tables[AAA_SERVER_GROUP_PRIO_TABLE], new_uuid=None)
    setattr(default_row, AAA_SERVER_GROUP_PRIO_SESSION_TYPE, AAA_SERVER_GROUP_PRIO_SESSION_TYPE_DEFAULT)
    prio_list_authorization[PRIO_ZERO] = none_row
    setattr(default_row, AAA_AUTHORIZATION_GROUP_PRIOS, prio_list_authorization)
    prio_list_authentication[PRIO_ZERO] = local_row
    setattr(default_row, AAA_AUTHENTICATION_GROUP_PRIOS, prio_list_authentication)

    txn.commit_block()

    default_sshd_config()

    default_row_initialized = 1
    return True


#---------------------------check_for_row_initialization ----------
def check_for_row_initialization():
    '''
    Check if add_row_information initialized properly,
    if initialization is not done, go and add  default row
    '''
    global idl

    # Check the OVS-DB/File status to see if initialization has completed.
    for ovs_rec in idl.tables[SYSTEM_TABLE].rows.itervalues():
        if not ovs_rec.aaa:
            add_default_row()

def  get_source_interface(protocol):
    '''
    Get tacacs/radius source interface configuration
    '''
    global radius_source_interface
    global tacacs_source_interface

    if protocol == AAA_RADIUS:
        radius_source_interface = vrf_utils.get_source_interface(idl, protocol)
        vlog.info("radius_source_interface = %s\n" % (radius_source_interface))

    if protocol == AAA_TACACS:
        tacacs_source_interface = vrf_utils.get_source_interface(idl, protocol)
        vlog.info("tacacs_source_interface = %s\n" % (tacacs_source_interface))

def get_src_ip_dstn_ns(source_interface):
    '''
    Get source ip and destination namespace from source interface
    '''
    dstn_ns = None

    mgmt_ip = vrf_utils.get_mgmt_ip(idl)
    vlog.info("mgmt_ip = %s\n" % (mgmt_ip))

    if source_interface is None:
        return source_interface, dstn_ns

    if source_interface != mgmt_ip:
        vrf_name = vrf_utils.get_vrf_name_from_ip(idl, source_interface)
        vlog.info("vrf_name = %s\n" % (vrf_name))

        dstn_ns = vrf_utils.get_namespace_from_vrf(idl, vrf_name)

    return source_interface, dstn_ns

#---------------------- update_ssh_config_file ---------------------
def update_ssh_config_file():
    '''
    modify sshd_config file, based on the ssh authentication method
    configured in aaa column
    '''
    passkey = "no"
    publickey = "no"
    sftpserver_enable = False

    for ovs_rec in idl.tables[SYSTEM_TABLE].rows.itervalues():
        if ovs_rec.aaa:
            for key, value in ovs_rec.aaa.items():
                if key == SSH_PASSKEY_AUTHENTICATION_ENABLE:
                    if value == AUTH_KEY_ENABLE:
                        passkey = "yes"
                elif key == SSH_PUBLICKEY_AUTHENTICATION_ENABLE:
                    if value == AUTH_KEY_ENABLE:
                        publickey = "yes"

    for ovs_rec in idl.tables[SYSTEM_TABLE].rows.itervalues():
        if ovs_rec.other_config and ovs_rec.other_config is not None:
            for key, value in ovs_rec.other_config.iteritems():
                if key == SFTP_SERVER_CONFIG:
                    if value == "true":
                        sftpserver_enable = True
                # modify the openssh banner files, this requires root access
                if key == BANNER:
                    with open(BANNER_FILE, "w") as f:
                        f.write(value + '\n')
                if key == BANNER_EXEC:
                    with open(MOTD_FILE, "w") as f:
                        f.write(value + '\n')

    # Add default values if not present, later change to values present in DB
    default_sshd_config()

    with open(SSHD_CONFIG, "r") as f:
        contents = f.readlines()

    for index, line in enumerate(contents):
        if "PubkeyAuthentication yes" in line or "PubkeyAuthentication no" \
           in line:
            del contents[index]
            contents.insert(index, "PubkeyAuthentication " + publickey + "\n")
        elif "PasswordAuthentication yes" \
             in line or "PasswordAuthentication no" in line:
            del contents[index]
            contents.insert(index, "PasswordAuthentication " + passkey + "\n")
        elif "Subsystem	sftp	/usr/lib/openssh/sftp-server" in line:
            if sftpserver_enable is True:
                del contents[index]
                contents.insert(
                    index, "Subsystem	sftp	/usr/lib/openssh/sftp-server" + "\n")
            else:
                del contents[index]
                contents.insert(
                    index, "#Subsystem	sftp	/usr/lib/openssh/sftp-server" + "\n")

    with open(SSHD_CONFIG, "w") as f:
        contents = "".join(contents)
        f.write(contents)

# ----------------------- get_server_list -------------------
def get_server_list(session_type):

    server_list = []
    global global_tacacs_passkey, global_tacacs_timeout, global_tacacs_auth
    global_tacacs_passkey = TACACS_SERVER_PASSKEY_DEFAULT
    global_tacacs_timeout = TACACS_SERVER_TIMEOUT_DEFAULT
    global_tacacs_auth = TACACS_PAP

    for ovs_rec in idl.tables[SYSTEM_TABLE].rows.itervalues():
        if ovs_rec.aaa and ovs_rec.aaa is not None:
            for key, value in ovs_rec.aaa.iteritems():
                if key == GBL_TACACS_SERVER_TIMEOUT:
                    global_tacacs_timeout = value
                if key == GBL_TACACS_SERVER_AUTH_TYPE:
                    global_tacacs_auth = value
                if key == GBL_TACACS_SERVER_PASSKEY:
                    global_tacacs_passkey = value
                if key == AAA_FAIL_THROUGH:
                    global AAA_FAIL_THROUGH_ENABLED

                    if value == AAA_TRUE_FLAG:
                        AAA_FAIL_THROUGH_ENABLED = True
                    else:
                        AAA_FAIL_THROUGH_ENABLED = False

    for ovs_rec in idl.tables[AAA_SERVER_GROUP_PRIO_TABLE].rows.itervalues():
        if ovs_rec.session_type != session_type:
            continue

        size = len(ovs_rec.authentication_group_prios)
        if size == 1 and ovs_rec.authentication_group_prios.keys()[0] == PRIO_ZERO:
            vlog.info("AAA: Default local authentication configured\n")
        else:
            for prio, group in sorted(ovs_rec.authentication_group_prios.iteritems()):
                if group is None:
                    continue

                vlog.info("AAA: group_name = %s, group_type = %s\n" % (group.group_name, group.group_type))

                server_table = ""
                if group.group_type == AAA_TACACS_PLUS:
                    server_table = TACACS_SERVER_TABLE
                elif group.group_type == AAA_RADIUS:
                    server_table = RADIUS_SERVER_TABLE
                elif group.group_type == AAA_LOCAL:
                    server_list.append((0, group.group_type))

                if server_table == RADIUS_SERVER_TABLE or server_table == TACACS_SERVER_TABLE:
                    group_server_dict = {}
                    for server in idl.tables[server_table].rows.itervalues():
                        vlog.info("AAA: Server %s group = %s group_prio = %s default_prio = %s\n" %
                                   (server.ip_address, server.group[0].group_name, server.group_priority, server.default_priority))

                        if server.group[0] == group:
                            if (server.group_priority == PRIO_ZERO):
                                group_server_dict[server.default_priority] = server
                            else:
                                group_server_dict[server.group_priority] = server

                    vlog.info("AAA: group_server_dict = %s\n" % (group_server_dict))

                    for server_prio, server in sorted(group_server_dict.iteritems()):
                        server_list.append((server, group.group_type))

    return server_list

# ----------------------- modify_common_auth_access_file -------------------
def modify_common_auth_access_file(server_list):
    '''
    modify common-auth-access file, based on RADIUS, TACACS+ and local
    values set in the DB
    '''
    global tacacs_source_interface
    src_ip = None
    dstn_ns = None

    if tacacs_source_interface is not None:
        src_ip, dstn_ns = get_src_ip_dstn_ns(tacacs_source_interface)

    vlog.info("##### tacacs_src_interface = %s, radius_src_interface = %s," \
        " src_ip = %s, dstn_ns = %s ########" \
        % (str(tacacs_source_interface), str(radius_source_interface), \
        str(src_ip), str(dstn_ns)))

    vlog.info("AAA: server_list = %s\n" % server_list)
    if not server_list:
        vlog.info("AAA: server_list is empty. Adding default local")

        server_list.append((0, AAA_LOCAL))

    file_header = "# THIS IS AN AUTO-GENERATED FILE\n" \
                  "#\n" \
                  "# /etc/pam.d/common-auth- authentication settings common to all services\n" \
                  "# This file is included from other service-specific PAM config files,\n" \
                  "# and should contain a list of the authentication modules that define\n" \
                  "# the central authentication scheme for use on the system\n" \
                  "# (e.g., /etc/shadow, LDAP, Kerberos, etc.). The default is to use the\n" \
                  "# traditional Unix authentication mechanisms.\n" \
                  "#\n" \
                  "# here are the per-package modules (the \"Primary\" block)\n"

    file_footer = "#\n" \
                  "# here's the fallback if no module succeeds\n" \
                  "auth    requisite                       pam_deny.so\n" \
                  "# prime the stack with a positive return value if there isn't one already;\n" \
                  "# this avoids us returning an error just because nothing sets a success code\n" \
                  "# since the modules above will each just jump around\n" \
                  "auth    required                        pam_permit.so\n" \
                  "# and here are more per-package modules (the \"Additional\" block)\n"

    common_auth_access_filename = PAM_ETC_CONFIG_DIR + "common-auth-access"

    with open(common_auth_access_filename, "w") as f:

        # Write the file header
        f.write(file_header)

        # Now write the server list to the config file
        PAM_CONTROL_VALUE = "[success=done new_authtok_reqd=done default=ignore auth_err=die]"
        if AAA_FAIL_THROUGH_ENABLED:
            PAM_CONTROL_VALUE = "sufficient"
            # Note: "sufficient" is same as [success=done new_authtok_reqd=done default=ignore]

        for server, server_type in server_list[:-1]:
            auth_line = ""
            if server_type == AAA_LOCAL:
                auth_line = "auth\t" + PAM_CONTROL_VALUE + "\t" + PAM_LOCAL_MODULE + " nullok\n"
            elif server_type == AAA_TACACS_PLUS:
                ip_address = server.ip_address
                tcp_port = server.tcp_port
                if len(server.timeout) == 0:
                    timeout = global_tacacs_timeout
                else:
                    timeout = server.timeout[0]
                if len(server.auth_type) == 0:
                    auth_type = global_tacacs_auth
                else:
                    auth_type = server.auth_type[0]
                if len(server.passkey) == 0:
                    passkey = global_tacacs_passkey
                else:
                    passkey = server.passkey[0]

                if dstn_ns is not None:
                    auth_line = "auth\t" + PAM_CONTROL_VALUE + "\t" + PAM_TACACS_MODULE + "\tdebug server=" + ip_address + \
                        ":" + str(tcp_port) + " secret=" + str(passkey) + " login=" + auth_type + " timeout=" + str(timeout) + \
                        " dstn_namespace=" + dstn_ns +  " source_ip=" + str(src_ip) + " \n"
                else:
                    auth_line = "auth\t" + PAM_CONTROL_VALUE + "\t" + PAM_TACACS_MODULE + "\tdebug server=" + ip_address + \
                        ":" + str(tcp_port) + " secret=" + str(passkey) + " login=" + auth_type + " timeout=" + str(timeout) + "\n"

            f.write(auth_line)

        # Print the last element
        server = server_list[-1][0]
        server_type = server_list[-1][1]
        auth_line = ""
        if server_type == AAA_LOCAL:
            auth_line = "auth\t[success=1 default=ignore]\t" + PAM_LOCAL_MODULE + " nullok\n"
        elif server_type == AAA_TACACS_PLUS:
            ip_address = server.ip_address
            tcp_port = server.tcp_port
            if len(server.timeout) == 0:
                timeout = global_tacacs_timeout
            else:
                timeout = server.timeout[0]
            if len(server.auth_type) == 0:
                auth_type = global_tacacs_auth
            else:
                auth_type = server.auth_type[0]
            if len(server.passkey) == 0:
                passkey = global_tacacs_passkey
            else:
                passkey = server.passkey[0]

            if dstn_ns is not None:
                auth_line = "auth\t[success=1 default=ignore]\t" + PAM_TACACS_MODULE + "\tdebug server=" + ip_address + \
                    " secret=" + str(passkey) + " login=" + auth_type + " timeout=" + str(timeout) + \
                    " dstn_namespace=" + dstn_ns +  " source_ip=" + str(src_ip) + " \n"
            else:
                auth_line = "auth\t[success=1 default=ignore]\t" + PAM_TACACS_MODULE + "\tdebug server=" + ip_address + \
                    " secret=" + str(passkey) + " login=" + auth_type + " timeout=" + str(timeout) + " \n"

        f.write(auth_line)

        # Write the file footer
        f.write(file_footer)

#---------------- aaa_reconfigure() ----------------
def aaa_util_reconfigure():
    '''
    Check system initialization, add default rows and update files accordingly
    based on the values in DB
    '''

    global system_initialized
    global default_row_initialized

    if system_initialized == 0:
        rc = system_is_configured()
        if rc is False:
            return

    if default_row_initialized == 0:
        check_for_row_initialization()

    update_ssh_config_file()

    get_source_interface(AAA_TACACS)
    #get_source_interface(AAA_RADIUS)
    vlog.info("##### tacacs_src_interface = %s, radius_src_interface = %s ########" \
        % (str(tacacs_source_interface), str(radius_source_interface)))

    # TODO: For now we're calling the functionality to configure
    # TACACS+ PAM config files after all RADIUS config is done
    # This way we can still test RADIUS by not configuring TACACS+
    # To unconfigure TACACS+ for now, just use -
    # no aaa authentication login default
    server_list = get_server_list("default")
    modify_common_auth_access_file(server_list)

    return

#----------------- aaa_run() -----------------------
def aaa_util_run():
    '''
    Run idl, and call reconfigure function when there is a change in DB \
   sequence number. \
    '''

    global idl
    global seqno

    idl.run()

    if seqno != idl.change_seqno:
        aaa_util_reconfigure()
        seqno = idl.change_seqno

    return


#----------------- main() -------------------
def main():

    global exiting
    global idl
    global seqno

    parser = argparse.ArgumentParser()
    parser.add_argument('-d', '--database', metavar="DATABASE",
                        help="A socket on which ovsdb-server is listening.",
                        dest='database')

    ovs.vlog.add_args(parser)
    ovs.daemon.add_args(parser)
    args = parser.parse_args()
    ovs.vlog.handle_args(args)
    ovs.daemon.handle_args(args)

    if args.database is None:
        remote = def_db
    else:
        remote = args.database

    schema_helper = ovs.db.idl.SchemaHelper(location=ovs_schema)
    schema_helper.register_columns(SYSTEM_TABLE, ["cur_cfg"])
    schema_helper.register_columns(SYSTEM_TABLE, ["other_config"])
    schema_helper.register_columns(SYSTEM_TABLE, ["mgmt_intf_status"])
    schema_helper.register_columns(PORT_TABLE, ["ip4_address", "name"])
    schema_helper.register_columns(VRF_TABLE, ["name", "ports", "table_id", "source_ip", "source_interface"])

    schema_helper.register_columns(
        SYSTEM_TABLE,
        [SYSTEM_AAA_COLUMN, SYSTEM_OTHER_CONFIG,
         SYSTEM_AUTO_PROVISIONING_STATUS_COLUMN])

    schema_helper.register_columns(SYSTEM_TABLE,
                                   [SYSTEM_RADIUS_SERVER_COLUMN])
    schema_helper.register_columns(TACACS_SERVER_TABLE,
                                   [TACACS_SERVER_IPADDRESS,
                                    TACACS_SERVER_PORT,
                                    TACACS_SERVER_PASSKEY,
                                    TACACS_SERVER_TIMEOUT,
                                    TACACS_SERVER_AUTH_TYPE,
                                    TACACS_SERVER_GROUP,
                                    TACACS_SERVER_GROUP_PRIO,
                                    TACACS_SERVER_DEFAULT_PRIO])
    schema_helper.register_columns(AAA_SERVER_GROUP_TABLE,
                                   [AAA_SERVER_GROUP_IS_STATIC,
                                    AAA_SERVER_GROUP_NAME,
                                    AAA_SERVER_GROUP_TYPE])
    schema_helper.register_columns(AAA_SERVER_GROUP_PRIO_TABLE,
                                   [AAA_SERVER_GROUP_PRIO_SESSION_TYPE,
                                    AAA_AUTHENTICATION_GROUP_PRIOS,
                                    AAA_AUTHORIZATION_GROUP_PRIOS])

    idl = ovs.db.idl.Idl(remote, schema_helper)

    ovs.daemon.daemonize()

    ovs.unixctl.command_register("exit", "", 0, 0, unixctl_exit, None)
    error, unixctl_server = ovs.unixctl.server.UnixctlServer.create(None)
    if error:
        ovs.util.ovs_fatal(error, "could not create unixctl server", vlog)

    seqno = idl.change_seqno  # Sequence number when last processed the db

    while not exiting:
        unixctl_server.run()

        aaa_util_run()

        if exiting:
            break

        poller = ovs.poller.Poller()
        unixctl_server.wait(poller)
        idl.wait(poller)
        poller.block()

    # Daemon Exit
    unixctl_server.close()
    idl.close()

    return

if __name__ == '__main__':
    try:
        main()
    except SystemExit:
        # Let system.exit() calls complete normally
        raise
    except:
        vlog.exception("traceback")
        sys.exit(ovs.daemon.RESTART_EXIT_CODE)
