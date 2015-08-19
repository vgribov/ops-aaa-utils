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
import argparse
import json
import urllib2
import httplib
import cookielib
from time import sleep

import ovs.dirs
from ovs.db import error
from ovs.db import types
import ovs.util
import ovs.db.idl

# ovs definitions
idl = None
# HALON_TODO: Need to pull this from the build env
def_db = 'unix:/var/run/openvswitch/db.sock'

# Configuration file definitions
saved_config = None
# HALON_TODO: Need to pull these three from the build env
cfgdb_schema = '/usr/share/openvswitch/configdb.ovsschema'
ovs_schema = '/usr/share/openvswitch/vswitch.ovsschema'
type_startup_config = "startup"
max_miliseconds_to_wait_for_config_data = 30

OPEN_VSWITCH_TABLE = "Open_vSwitch"
HALON_TRUE = "True"
HALON_FALSE = "False"
PERFORMED = "performed"
URL = "url"
AUTOPROVISION_FILE = '/var/tmp/autoprovision'

def is_system_configured(data):
    '''
    Check the configuration initialization completed Open_vSwitch:cur_cfg
    configuration completed: return True
    else: return False
    '''

    for ovs_rec in data[OPEN_VSWITCH_TABLE].rows.itervalues():
        if ovs_rec.cur_cfg:
            if ovs_rec.cur_cfg > 0:
                return True
            else:
                return False

    return False

#------------------ get_config() ----------------
def get_config(idl_cfg):
    '''
    Walk through the rows in the config table (if any)
    looking for a row with type == startup.

    If found, set global variable saved_config to the content
    of the "config" field in that row.
    '''

    global saved_config

    #Note: You can't tell the difference between the config table not
    #      existing (that is the configdb is not there) or just that there

    #      are no rows in the config table.
    tbl_found = False
    for ovs_rec in idl_cfg.tables["config"].rows.itervalues():
        tbl_found = True
        if ovs_rec.type:
            if ovs_rec.type == type_startup_config:
                if ovs_rec.config:
                    saved_config = ovs_rec.config
                else:
                    print("startup config row does not have config column")
                return

    if not tbl_found:
        print("No rows found in the config table")

#------------------ check_for_startup_config() ----------------
def check_for_startup_config(remote):
    '''
    Connect to the db server and specify the configdb database.
    Look for an entry with type=startup
    If exists, read the configuration.
    '''

    global saved_config

    saved_config = None

    schema_helper_cfg = ovs.db.idl.SchemaHelper(location=cfgdb_schema)
    schema_helper_cfg.register_table("config")

    idl_cfg = ovs.db.idl.Idl(remote, schema_helper_cfg)

    '''
    The wait time is 30 * 0.1 = 3 seconds
    '''
    cnt = max_miliseconds_to_wait_for_config_data
    while not idl_cfg.run() and cnt > 0:
        cnt -= 1
        sleep(.1)

    get_config(idl_cfg)

    idl_cfg.close()

    return

def fetch_autoprovision_script(url):
    ret = False
    try :
        cj = cookielib.CookieJar()
        header = { 'User-Agent' : 'OPS-AutoProvision/1.0', 'OPS-MANUFACTURER': 'OpenSwitch', 'OPS-VENDOR': 'OpenSwitch' }
        opener = urllib2.build_opener(urllib2.HTTPCookieProcessor(cj))
        request = urllib2.Request(url, None, header)

        print("Sending HTTP GET to %s" % url)
        f = opener.open(request)
        data = f.read()
        f.close()
        opener.close()
    except urllib2.HTTPError, e:
        print('HTTPError = ' + str(e.code))
        return ret
    except urllib2.URLError, e:
        print('URLError = ' + str(e.reason))
        return ret
    except httplib.HTTPException, e:
        print('HTTPException = '+ str(e.reason))
        return ret
    except Exception, e:
        print('generic exception: ' + str(e))
        return ret

    if os.path.exists(AUTOPROVISION_FILE):
        os.remove(AUTOPROVISION_FILE)

    if ("HALON-AUTOPROVISIONING" in data):
        FILE = open(AUTOPROVISION_FILE, "wb")
        FILE.write(data)
        FILE.close()
        ret = True
    else :
        print("Error, downloaded autoprovision script doesn't contain HALON-AUTOPROVISIONING string in comment")
        ret = False

    return ret

def is_autoprovision_performed():
    global idl

    ret = False
    for ovs_rec in idl.tables[OPEN_VSWITCH_TABLE].rows.itervalues():
        if ovs_rec.auto_provisioning_status:
            for key, value in ovs_rec.auto_provisioning_status.items():
                if key == PERFORMED and value == HALON_TRUE:
                    ret = True

    return ret

def update_autoprovision_status(performed_value, url):
    global idl

    data = {}

    data[PERFORMED] = performed_value
    data[URL] = url
    # create the transaction
    txn = ovs.db.idl.Transaction(idl)
    for ovs_rec in idl.tables[OPEN_VSWITCH_TABLE].rows.itervalues():
        break

    setattr(ovs_rec, "auto_provisioning_status", data)

    txn.commit_block()

    return True


    ###############################  main  ###########################
def main():
    global idl
    argv = sys.argv
    n_args = 2

    if len(argv) !=  n_args :
        print("Requires %d arguments but %d provided \n" % (n_args, len(argv)))
        return

    # Locate default config if it exists
    schema_helper = ovs.db.idl.SchemaHelper(location=ovs_schema)
    schema_helper.register_columns(OPEN_VSWITCH_TABLE, \
                ["cur_cfg", "auto_provisioning_status"])

    idl = ovs.db.idl.Idl(def_db, schema_helper)

    seqno = idl.change_seqno    # Sequence number when we last processed the db

    '''
    The wait time is 30 * 0.1 = 3 seconds
    '''
    cnt = max_miliseconds_to_wait_for_config_data
    while not idl.run() and cnt > 0:
        cnt -= 1
        sleep(.1)


    #Wait till system is configured
    while not is_system_configured(idl.tables):
        sleep(1)

    if os.path.exists('/etc/autoprovision'):
        print("Autoprovisioning already completed")
        update_autoprovision_status(HALON_TRUE, argv[1])
        idl.close()
        return

    check_for_startup_config(def_db)

    if(saved_config != None):
        print("startup config present, skipping autoprovision")
        idl.close()
        return

    if(is_autoprovision_performed() == True):
        idl.close()
        return

    if(fetch_autoprovision_script(argv[1]) == False):
        print("Downloading autoprovisioning script failed")
        idl.close()
        return

    sys.stdout.flush()

    ret = 1
    if os.path.exists(AUTOPROVISION_FILE):
        ret = os.system('chmod +x ' + AUTOPROVISION_FILE)
        ret = os.system(AUTOPROVISION_FILE)
        if (ret == 0 ):
            update_autoprovision_status(HALON_TRUE, argv[1])
            os.system('touch /etc/autoprovision')
            print("Autoprovision status: performed = %s URL =  %s" % (HALON_TRUE, argv[1]))
        else:
            print("Error, autoprovision script returned error %d" % ret)

    idl.close()

if __name__ == '__main__':
    try:
        main()
    except error.Error, e:
        print("Error: \"%s\" \n" % e)
