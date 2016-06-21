# Copyright (C) 2016 Hewlett Packard Enterprise Development LP
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

from time import sleep
from os.path import realpath, join, dirname

TOPOLOGY = """
#               +-------+
# +-------+     |       |
# |  sw1  <----->   h1  |
# +-------+     |       |
#               +-------+

# Nodes
[type=openswitch name="Switch 1"] sw1
[type=oobmhost name="Host 1" image="openswitch/lighttpd-ubuntu:latest"] h1

# Ports
[force_name=oobm] sw1:sp1

# Links
sw1:sp1 -- h1:if01
"""

HTTP_SERVER_ROOT_PATH = "/var/www/servers/www.example.org/pages/"
SCRIPT_NAME = "autoprovision"
TEST_ECHO_STRING = "Hello from Autoprovision script"
LIGHTTPD_CONFIG = join(dirname(realpath(__file__)), "lighttpd.conf")


def setuphttpserver(h1):
    ''' This function is to setup http server in the ubuntu image
    we are referring to
    '''

    # Configure lighttpd conf file and root path of server
    h1("mkdir -p " + HTTP_SERVER_ROOT_PATH)
    with open(LIGHTTPD_CONFIG) as f_config:
        config = f_config.read()

    h1(config)

    h1("killall -9 lighttpd")
    sleep(1)
    out = h1("lighttpd -t -f ~/lighttpd.conf")
    out += h1("echo ")

    if "Syntax OK" in out:
        out = h1("lighttpd -f ~/lighttpd.conf")
    else:
        assert "Syntax OK" in out, "Failed to setup lighttpd server"

    return True


def gethostip(h1):
    ''' This function is to get host IP addess'''
    out = h1("ifconfig eth0")
    out = h1("ifconfig eth0")
    host_ipaddress = out.split("\n")[1].split()[1][5:]
    return host_ipaddress


def setupautoprovisionscript(h1):
    ''' This function is to setup autoprovision script in http server '''

    h1("touch " + HTTP_SERVER_ROOT_PATH + SCRIPT_NAME)

    h1("echo \'#!/bin/sh\' >>" + HTTP_SERVER_ROOT_PATH + SCRIPT_NAME)
    h1("echo \'#OPS-PROVISIONING\'>>" + HTTP_SERVER_ROOT_PATH + SCRIPT_NAME)
    h1("echo echo " + TEST_ECHO_STRING + " >>" + HTTP_SERVER_ROOT_PATH +
       SCRIPT_NAME)

    return True


def setupnet(h1):
    setuphttpserver(h1)

    setupautoprovisionscript(h1)


def executeautoprovision(sw1, h1, step):
    ''' This function download autoprovision script from http server
    and execute it'''
    step('\n########## Executing Autoprovision ##########\n')
    host_ipaddress = gethostip(h1)
    htttp_url = "http://" + host_ipaddress + "/autoprovision"

    out = sw1("autoprovision " + htttp_url, shell="bash")

    out += sw1("end")

    assert TEST_ECHO_STRING in out, \
        "Failed in executing autoprovision script"
    step("### Passed:Executing downloaded autoprovision script ###\n")

    out = sw1("show autoprovision")
    out += sw1("end")

    assert htttp_url in out, \
        "Failed in updating autoprovision status in DB"
    step("### Passed: Verify autoprovision status updated in DB ###\n")

    step('\n### Executing Autoprovision again, it should not perform ###\n')
    out = sw1("autoprovision " + htttp_url, shell="bash")
    out += sw1("end")

    assert "Autoprovisioning already completed" in out, \
        "Failed in executing autoprovision script again"
    step("### Passed:Executing autoprovision script again,"
         "autoprovision not performed  ###\n")


def test_autoprovisionfeature(topology, step):
    sw1 = topology.get('sw1')
    h1 = topology.get('h1')

    assert sw1 is not None
    assert h1 is not None

    setupnet(h1)

    executeautoprovision(sw1, h1, step)
