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
SYSTEM_TACACS_CONFIG_COLUMN = "tacacs_config"
SYSTEM_RADIUS_SERVER_COLUMN = "radius_servers"
RADIUS_SERVER_TABLE = "Radius_Server"
AAA_SERVER_GROUP_TABLE = "AAA_Server_Group"

SYSTEM_AUTO_PROVISIONING_STATUS_COLUMN = "auto_provisioning_status"

AAA_RADIUS = "radius"
AAA_RADIUS_AUTH = "radius_auth"
AAA_TACACS = "tacacs"
AAA_TACACS_PLUS = "tacacs+"
AAA_LOCAL = "local"
AAA_TACACS_AUTH = "tacacs_auth"
AAA_FALLBACK = "fallback"
OPS_TRUE = "true"
OPS_FALSE = "false"

AAA_SERVER_GROUP_PRIORITY = "priority"
AAA_SERVER_GROUP_NAME = "group_name"
AAA_SERVER_GROUP_TYPE = "group_type"

RADIUS_SERVER_IPADDRESS = "ip_address"
RADIUS_SERVER_PORT = "udp_port"
RADIUS_SERVER_PASSKEY = "passkey"
RADIUS_SERVER_TIMEOUT = "timeout"
RADIUS_SERVER_RETRIES = "retries"
RADIUS_SEREVR_PRIORITY = "priority"

TACACS_SERVER_PORT = "tcp_port"
TACACS_SERVER_PASSKEY = "passkey"
TACACS_SERVER_TIMEOUT = "timeout"

SERVER_GROUP_PRIORITY_DEFAULT = -1
TACACS_SERVER_TCP_PORT_DEFAULT = "49"
TACACS_SERVER_PASSKEY_DEFAULT = "testing123-1"
TACACS_SERVER_TIMEOUT_DEFAULT = "5"

SSH_PASSKEY_AUTHENTICATION_ENABLE = "ssh_passkeyauthentication_enable"
SSH_PUBLICKEY_AUTHENTICATION_ENABLE = "ssh_publickeyauthentication_enable"
BANNER = "banner"
BANNER_EXEC = "banner_exec"
AUTH_KEY_ENABLE = "true"

SFTP_SERVER_CONFIG = "sftp_server_enable"

PERFORMED = "performed"
URL = "url"

RADIUS_PAP = "pap"
RADIUS_CHAP = "chap"

TACACS_PAP = "pap"
TACACS_CHAP = "chap"

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
        sleep(1)
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
    auto_provisioning_data = {}
    tacacs_data = {}
    local_group_data = {}
    tacacs_group_data = {}
    radius_group_data = {}

    # Default values for aaa column
    data[AAA_FALLBACK] = OPS_TRUE
    data[AAA_RADIUS] = OPS_FALSE
    data[AAA_RADIUS_AUTH] = RADIUS_PAP
    data[AAA_TACACS] = OPS_FALSE
    data[AAA_TACACS_AUTH] = TACACS_PAP
    data[SSH_PASSKEY_AUTHENTICATION_ENABLE] = AUTH_KEY_ENABLE
    data[SSH_PUBLICKEY_AUTHENTICATION_ENABLE] = AUTH_KEY_ENABLE

    # Default values for auto provisioning status column
    auto_provisioning_data[PERFORMED] = "False"
    auto_provisioning_data[URL] = ""

    # Default values for tacacs_config column
    tacacs_data[TACACS_SERVER_PORT] = TACACS_SERVER_TCP_PORT_DEFAULT
    tacacs_data[TACACS_SERVER_PASSKEY] = TACACS_SERVER_PASSKEY_DEFAULT
    tacacs_data[TACACS_SERVER_TIMEOUT] = TACACS_SERVER_TIMEOUT_DEFAULT

    # create the transaction
    txn = ovs.db.idl.Transaction(idl)
    for ovs_rec in idl.tables[SYSTEM_TABLE].rows.itervalues():
        break

    setattr(ovs_rec, SYSTEM_AAA_COLUMN, data)
    setattr(ovs_rec, SYSTEM_AUTO_PROVISIONING_STATUS_COLUMN,
            auto_provisioning_data)
    setattr(ovs_rec, SYSTEM_TACACS_CONFIG_COLUMN, tacacs_data)

    # create default server groups: local, tacacs+ and radius
    local_row = txn.insert(idl.tables[AAA_SERVER_GROUP_TABLE], new_uuid=None)
    setattr(local_row, AAA_SERVER_GROUP_PRIORITY, 0)
    setattr(local_row, AAA_SERVER_GROUP_NAME, AAA_LOCAL)
    setattr(local_row, AAA_SERVER_GROUP_TYPE, AAA_LOCAL)

    tacacs_row = txn.insert(idl.tables[AAA_SERVER_GROUP_TABLE], new_uuid=None)
    setattr(tacacs_row, AAA_SERVER_GROUP_PRIORITY, SERVER_GROUP_PRIORITY_DEFAULT)
    setattr(tacacs_row, AAA_SERVER_GROUP_NAME, AAA_TACACS_PLUS)
    setattr(tacacs_row, AAA_SERVER_GROUP_TYPE, AAA_TACACS_PLUS)

    radius_row = txn.insert(idl.tables[AAA_SERVER_GROUP_TABLE], new_uuid=None)
    setattr(radius_row, AAA_SERVER_GROUP_PRIORITY, SERVER_GROUP_PRIORITY_DEFAULT)
    setattr(radius_row, AAA_SERVER_GROUP_NAME, AAA_RADIUS)
    setattr(radius_row, AAA_SERVER_GROUP_TYPE, AAA_RADIUS)

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
    return True


# ---------------- update_server_file -----------------
def update_server_file():
    '''
    Based on ovsdb radius server table entries
    update radius client file accordingly
    '''
    global idl

    insert_server_info = ["" for x in range(64)]
    radius_ip = 0
    priority = 0
    radius_port = 0
    radius_passkey = 0
    radius_timeout = 0
    row_count = 0
    for ovs_rec in idl.tables[RADIUS_SERVER_TABLE].rows.itervalues():
        if ovs_rec.ip_address:
            radius_ip = ovs_rec.ip_address
        if ovs_rec.udp_port:
            radius_port = ",".join(str(i) for i in ovs_rec.udp_port)
        if ovs_rec.passkey:
            radius_passkey = "".join(ovs_rec.passkey)
        if ovs_rec.timeout:
            radius_timeout = ",".join(str(i) for i in ovs_rec.timeout)
        if ovs_rec.priority:
            priority = ovs_rec.priority - 1

        insert_server_info[priority] = radius_ip + ":" + radius_port + " " + \
            radius_passkey + " " + radius_timeout
        row_count += 1

    with open(RADIUS_CLIENT, "w+") as f:
        f.write("\n".join(insert_server_info[count] for count in range(0,
                                                           row_count)))

    radius_passkey = 0

    return


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


# ----------------------- modify_common_auth_file -------------------
def modify_common_auth_session_file(fallback_value, radius_value,
                                    radius_xap_value):
    '''
    modify common-auth-access files, based on radius and fallback
    values set in the DB
    '''
    radius_retries = "1"

    for ovs_rec in idl.tables[RADIUS_SERVER_TABLE].rows.itervalues():
        if ovs_rec.retries:
            radius_retries = ",".join(str(i) for i in ovs_rec.retries)

    local_auth = [" ", " "]
    radius_auth = [" ", " "]
    fallback_and_radius_auth = [" ", " "]
    fallback_local_auth = [" ", " "]
    filename = [" ", " "]

    # If radius with CHAP is enabled then for all auth
    # functions use pam_radius_chap_auth.so module.
    # Other functions, e.g. session, accounting etc. should
    # continue to use pam_radius_auth.so module

    if radius_xap_value == RADIUS_CHAP:
        radius_lib_suffix = "chap_auth.so"
    else:
        radius_lib_suffix = "auth.so"

    local_auth[0] = "auth\t[success=1 default=ignore]\tpam_unix.so nullok\n"
    radius_auth[0] = \
        "auth\t[success=1 default=ignore]\tpam_radius_"
    fallback_and_radius_auth[0] = \
        "auth\t[success=2 authinfo_unavail=ignore default=1]\tpam_radius_"

    fallback_local_auth[0] =  \
        "auth\t[success=1 default=ignore]\tpam_unix.so\ttry_first_pass\n"

    local_auth[1] = "session\trequired\tpam_unix.so\n"
    radius_auth[1] = "session\trequired\tpam_radius_auth.so\n"

    fallback_and_radius_auth[1] = \
        "session\t[success=done new_authtok_reqd=done authinfo_unavail=ignore \
        session_err=ignore default=die]\tpam_radius_auth.so\n"

    fallback_local_auth[1] = "session\trequired\tpam_unix.so\n"

    filename[0] = PAM_ETC_CONFIG_DIR + "common-auth-access"
    filename[1] = PAM_ETC_CONFIG_DIR + "common-session-access"
    for count in range(0, 2):
        with open(filename[count], "r") as f:
            contents = f.readlines()
        for index, line in enumerate(contents):
            if local_auth[count] in line or radius_auth[count] in line:
                del contents[index]
                break
            elif fallback_and_radius_auth[count] in line:
                del contents[index]
                del contents[index]
                break

        if radius_value == OPS_FALSE:
            contents.insert(index, local_auth[count])

        if radius_value == OPS_TRUE and fallback_value == OPS_FALSE  \
           and count == 0:
            contents.insert(index, radius_auth[count] + radius_lib_suffix +
                            "\tretry=" + radius_retries + "\n")

        if radius_value == OPS_TRUE and fallback_value == OPS_FALSE and  \
           count == 1:
            contents.insert(index, radius_auth[count])

        if radius_value == OPS_TRUE and fallback_value == OPS_TRUE and \
           count == 0:
            contents.insert(index, fallback_local_auth[count])
            contents.insert(index, fallback_and_radius_auth[count] +
                            radius_lib_suffix + "\tretry=" +
                            radius_retries + "\n")

        if radius_value == OPS_TRUE and fallback_value == OPS_TRUE \
           and count == 1:
            contents.insert(index, fallback_local_auth[count])
            contents.insert(index, fallback_and_radius_auth[count])

        with open(filename[count], "w") as f:
            contents = "".join(contents)
            f.write(contents)


#-------------------- update_access_files ---------------------
def update_access_files():
    '''
    Based on my_auth variable update auth and password files accordingly
    and modify session and auth files as well.
    '''
    global my_auth
    global count
    global idl

    passwdText = "pam_unix.so"
    radiusText = "pam_radius_auth.so"
    commonPasswordText = "pam_unix.so obscure sha512"
    fallback_value = OPS_TRUE
    radius_value = OPS_FALSE
    radius_auth_value = RADIUS_PAP
    # Hardcoded file path
    filename = [PAM_ETC_CONFIG_DIR + "common-password-access",
                PAM_ETC_CONFIG_DIR + "common-account-access"]

    # Count Max value is No. of files present in filename
    count = 0

    for ovs_rec in idl.tables[SYSTEM_TABLE].rows.itervalues():
        if ovs_rec.aaa:
            for key, value in ovs_rec.aaa.items():
                if key == AAA_FALLBACK:
                    fallback_value = value
                if key == AAA_RADIUS:
                    radius_value = value
                    if value == OPS_TRUE:
                        my_auth = "radius"
                    else:
                        my_auth = "passwd"
                if key == AAA_RADIUS_AUTH:
                    radius_auth_value = value

    # To modify common auth and common session files
    modify_common_auth_session_file(fallback_value, radius_value,
                                    radius_auth_value)

    # To modify common accounting and common password files
    for count in range(0, 2):
        with open(filename[count], 'r+') as f:
            newdata = f.read()
        if my_auth == "radius":
            if count == 0:
                newdata = newdata.replace(commonPasswordText, radiusText)
            else:
                newdata = newdata.replace(passwdText, radiusText)
        elif my_auth == "passwd":
            if count == 0:
                newdata = newdata.replace(radiusText, commonPasswordText)
            else:
                newdata = newdata.replace(radiusText, passwdText)

        with open(filename[count], 'w') as f:
            f.write(newdata)
        count += 1


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
        ret = check_for_row_initialization()
        if ret is False:
            return

    update_server_file()
    update_access_files()
    update_ssh_config_file()

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
    schema_helper.register_columns(
        SYSTEM_TABLE,
        [SYSTEM_AAA_COLUMN, SYSTEM_OTHER_CONFIG,
         SYSTEM_TACACS_CONFIG_COLUMN,
         SYSTEM_AUTO_PROVISIONING_STATUS_COLUMN])

    schema_helper.register_columns(SYSTEM_TABLE,
                                   [SYSTEM_RADIUS_SERVER_COLUMN])
    schema_helper.register_columns(RADIUS_SERVER_TABLE,
                                   [RADIUS_SERVER_IPADDRESS,
                                    RADIUS_SERVER_PORT,
                                    RADIUS_SERVER_PASSKEY,
                                    RADIUS_SERVER_TIMEOUT,
                                    RADIUS_SERVER_RETRIES,
                                    RADIUS_SEREVR_PRIORITY])
    schema_helper.register_columns(AAA_SERVER_GROUP_TABLE,
                                   [AAA_SERVER_GROUP_PRIORITY,
                                    AAA_SERVER_GROUP_NAME,
                                    AAA_SERVER_GROUP_TYPE])

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
