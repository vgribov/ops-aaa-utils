#!/usr/bin/env python
# Copyright (C) 2014-2015 Hewlett-Packard Development Company, L.P.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import os
import sys
import time
from time import sleep

import ovs.dirs
from ovs.db import error
from ovs.db import types
import ovs.daemon
import ovs.db.idl
import ovs.unixctl
import ovs.unixctl.server
import argparse
import ovs.vlog

# Assign my_auth to default local config
my_auth = "passwd"
local_seqno_value = 0

# This should be upated when new function is introduced
# in between of dispatcher list
BACK_TO_FILES_UPDATION = 2

# Ovs definition
idl = None

vlog = ovs.vlog.Vlog("aaautilspamcfg")
def_db = 'unix:/var/run/openvswitch/db.sock'

# Schema path
ovs_schema = '/usr/share/openvswitch/vswitch.ovsschema'

# Program control
exiting = False
PAM_ETC_CONFIG_DIR                = "/etc/pam.d/"
RADIUS_CLIENT                     = "/etc/raddb/server"
dispatch_list = []
OPEN_VSWITCH_TABLE                = "Open_vSwitch"
OPEN_VSWITCH_AAA_COLUMN           = "aaa"
OPEN_VSWITCH_RADIUS_SERVER_COLUMN = "radius_servers"
RADIUS_SERVER_TABLE               = "Radius_Server"

AAA_RADIUS                        = "radius"
AAA_FALLBACK                      = "fallback"
HALON_TRUE                        = "true"
HALON_FALSE                       = "false"

RADIUS_SERVER_IPADDRESS           = "ip_address"
RADIUS_SERVER_PORT                = "udp_port"
RADIUS_SERVER_PASSKEY             = "passkey"
RADIUS_SERVER_TIMEOUT             = "timeout"
RADIUS_SERVER_RETRIES             = "retries"

#---------------- unixctl_exit --------------------------
def unixctl_exit(conn, unused_argv, unused_aux):
    global exiting

    exiting = True
    conn.reply(None)

#------------------ db_get_system_status() ----------------
def db_get_system_status(data):
    '''
    Check the configuration initialization completed
    (Open_vSwitch:cur_cfg == true)
    '''
    for ovs_rec in data[OPEN_VSWITCH_TABLE].rows.itervalues():
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

    # Check the OVS-DB/File status to see if initialization has completed.
    if not db_get_system_status(idl.tables):
        # Delay a little before trying again
        sleep(1)
        return False

    return True

# ----------------- add_default_row -----------------------
def add_default_row():
    '''
    Add default values to the radius and fallback columns
    by default radius is false and fallback is true
    '''
    global idl

    data = {}

    data[AAA_FALLBACK] = HALON_TRUE
    data[AAA_RADIUS] = HALON_FALSE
    # create the transaction
    txn = ovs.db.idl.Transaction(idl)
    for ovs_rec in idl.tables[OPEN_VSWITCH_TABLE].rows.itervalues():
        break

    setattr(ovs_rec, OPEN_VSWITCH_AAA_COLUMN, data)

    txn.commit_block()

    return True


#---------------------------check_for_row_initialization ----------
def check_for_row_initialization():
    '''
    Check if add_row_information initialized properly,
    if initialization is not done, go and add  default row
    '''
    global idl
    global local_seqno_value

    local_seqno_value = idl.change_seqno + 1
    # Check the OVS-DB/File status to see if initialization has completed.
    for ovs_rec in idl.tables[OPEN_VSWITCH_TABLE].rows.itervalues():
        if not ovs_rec.aaa:
            add_default_row()
    return True

#------------- update_radius_client_and_pam_config_file -------------
def update_radius_client_and_pam_config_file():
    '''
    This calls functions for radius server files and pam configuration files
    updation.
    '''
    global local_seqno_value
    global idl

    if local_seqno_value == idl.change_seqno:
        return False

    update_server_file()
    update_access_files()

    local_seqno_value = idl.change_seqno

    return True

# ---------------- update_server_file -----------------
def update_server_file():
    '''
    Based on my_auth variable update server files accordingly
    '''
    global idl

    insert_server_info = [0 for x in range(64)]
    radius_ip = [0 for x in range(64)]
    radius_port = 0
    radius_passkey = 0
    radius_timeout = 0

    row_count = 0
    for ovs_rec in idl.tables[RADIUS_SERVER_TABLE].rows.itervalues():
        if ovs_rec.ip_address:
            radius_ip[row_count] = ovs_rec.ip_address
        if ovs_rec.udp_port:
            radius_port = ",".join(str(i) for i in ovs_rec.udp_port)
        if ovs_rec.passkey:
            radius_passkey = "".join(ovs_rec.passkey)
        if ovs_rec.timeout:
            radius_timeout = ",".join(str(i) for i in ovs_rec.timeout)

        insert_server_info[row_count] = radius_ip[row_count] + ":"+ radius_port + " " +  radius_passkey + " " + radius_timeout + " check "

        row_count += 1
    if row_count == 0:
        with open(RADIUS_CLIENT, 'w'): pass
        return

    with open(RADIUS_CLIENT, "r") as f:
        contents = f.readlines()
    index = 0
    count = 0

    for count in range(0,row_count):
        ip_check = 0
        for index, line in enumerate(contents):
            if radius_ip[count] in line:
                del contents[index]
                contents.insert(index,insert_server_info[count]+"\n")
                ip_check = 1
                break
        if ip_check == 0:
            index += 1
            contents.insert(index,insert_server_info[count]+"\n")

    index = 0
    for index, line in enumerate(contents):
        if "check" not in line:
            del contents[index]
    contents = [word.replace('check ','') for word in contents]
    with open(RADIUS_CLIENT, "w") as f:
        contents = "".join(contents)
        f.write(contents)

    return

# ----------------------- modify_common_auth_file -------------------
def modify_common_auth_session_file(fallback_value,radius_value):
    '''
    modify common-auth-access files, based on radius and fallback
    values set in the DB
    '''
    radius_retries = "1"

    for ovs_rec in idl.tables[RADIUS_SERVER_TABLE].rows.itervalues():
        if ovs_rec.retries:
            radius_retries = ",".join(str(i) for i in ovs_rec.retries)

    local_auth = [" " ," "]
    radius_auth = [" ", " "]
    fallback_and_radius_auth = [" ", " "]
    fallback_local_auth = [" "," "]
    filename = [" ", " "]

    local_auth[0] = "auth\t[success=1 default=ignore]\tpam_unix.so nullok\n"
    radius_auth[0] = "auth\t[success=1 default=ignore]\tpam_radius_auth.so\tretry="
    fallback_and_radius_auth[0] = "auth\t[success=2 authinfo_unavail=ignore default=1]\tpam_radius_auth.so\tretry="
    fallback_local_auth[0] = "auth\t[success=1 default=ignore]\tpam_unix.so\tuse_first_pass\n"

    local_auth[1] = "session\trequired\tpam_unix.so\n"
    radius_auth[1] = "session\trequired\tpam_radius_auth.so\n"
    fallback_and_radius_auth[1] = "session\t[success=done new_authtok_reqd=done authinfo_unavail=ignore default=die]\tpam_radius_auth.so\n"
    fallback_local_auth[1] = "session\trequired\tpam_unix.so\n"

    filename[0] = PAM_ETC_CONFIG_DIR + "common-auth-access"
    filename[1] = PAM_ETC_CONFIG_DIR + "common-session-access"
    for count in range(0,2):
        with open(filename[count], "r") as f:
            contents = f.readlines()
        cfgnow = 0;
        for index, line in enumerate(contents):
            if local_auth[count] in  line or radius_auth[count] in line:
                del contents[index]
                break
            elif fallback_and_radius_auth[count] in line:
                del contents[index]
                del contents[index]
                break

        if radius_value == HALON_FALSE:
            contents.insert(index, local_auth[count])

        if radius_value == HALON_TRUE and fallback_value == HALON_FALSE and count == 0:
            contents.insert(index, radius_auth[count]+ radius_retries + "\n")

        if radius_value == HALON_TRUE and fallback_value == HALON_FALSE and count == 1:
            contents.insert(index, radius_auth[count])

        if radius_value == HALON_TRUE and fallback_value == HALON_TRUE and count == 0:
            contents.insert(index, fallback_local_auth[count])
            contents.insert(index,fallback_and_radius_auth[count] + radius_retries + "\n")

        if radius_value == HALON_TRUE and fallback_value == HALON_TRUE and count == 1:
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

    # Hardcoded file path
    filename = [PAM_ETC_CONFIG_DIR + "common-password-access", \
                PAM_ETC_CONFIG_DIR + "common-account-access"]

    # Count Max value is No. of files present in filename
    count = 0

    for ovs_rec in idl.tables[OPEN_VSWITCH_TABLE].rows.itervalues():
        if ovs_rec.aaa:
            for key, value in ovs_rec.aaa.items():
                if key == AAA_FALLBACK:
                    fallback_value = value
                if key == AAA_RADIUS:
                    radius_value = value
                    if value == HALON_TRUE:
                        my_auth = "radius"
                    else:
                        my_auth = "passwd"

    # To modify common auth and common session files
    modify_common_auth_session_file(fallback_value, radius_value)

    # To modify common accounting and common password files
    for count in range(0,2):
        with open(filename[count],'r+') as f:
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

        with open(filename[count],'w') as f:
            f.write(newdata)
        count += 1

# ----------------- init_dispatcher --------------------
def init_dispatcher():
    '''
    Creates a list of functions to call in sequence
    Initializes loop_seq_no to zero.
    '''

    global dispatch_list
    global loop_seq_no

    dispatch_list = []

    # Each of these functions must return:
    #   True if the function has completed its job, or
    #   False if it needs to run again
    dispatch_list.append(system_is_configured)
    dispatch_list.append(check_for_row_initialization)
    dispatch_list.append(update_radius_client_and_pam_config_file)
    loop_seq_no = 0

# ---------------- dispatcher --------------------------
def dispatcher():
    '''
    Call next functions in the list
    If it returns true, increment the loop counter
    If run out of functions, terminate
    '''

    global dispatch_list
    global loop_seq_no

    if loop_seq_no < len(dispatch_list):
        rc = dispatch_list[loop_seq_no]()
        if rc:
            loop_seq_no += 1
    elif loop_seq_no == len(dispatch_list):
        loop_seq_no = BACK_TO_FILES_UPDATION

#----------------- main() -------------------
def main():

    global exiting
    global idl
    global loop_seq_no

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
    schema_helper.register_columns(OPEN_VSWITCH_TABLE, ["cur_cfg"])
    schema_helper.register_columns(OPEN_VSWITCH_TABLE, [OPEN_VSWITCH_AAA_COLUMN])
    schema_helper.register_columns(OPEN_VSWITCH_TABLE, [OPEN_VSWITCH_RADIUS_SERVER_COLUMN])
    schema_helper.register_columns(RADIUS_SERVER_TABLE, [RADIUS_SERVER_IPADDRESS, RADIUS_SERVER_PORT, \
                                                         RADIUS_SERVER_PASSKEY, RADIUS_SERVER_TIMEOUT, \
                                                         RADIUS_SERVER_RETRIES])


    idl = ovs.db.idl.Idl(remote, schema_helper)

    ovs.daemon.daemonize()

    ovs.unixctl.command_register("exit", "", 0, 0, unixctl_exit, None)
    error, unixctl_server = ovs.unixctl.server.UnixctlServer.create(None)
    if error:
        ovs.util.ovs_fatal(error, "could not create unixctl server", vlog)

    seqno = idl.change_seqno # Sequence number when we last processed the db

    init_dispatcher()

    while not exiting:
        unixctl_server.run()

        idl.run()
        # Call next method in the sequence
        dispatcher()

        if exiting:
            break;

        if seqno == idl.change_seqno:
            poller = ovs.poller.Poller()
            unixctl_server.wait(poller)
            idl.wait(poller)
            poller.block()
        seqno = idl.change_seqno

    #Daemon Exit
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
