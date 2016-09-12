# -*- coding: utf-8 -*-
# (C) Copyright 2015 Hewlett Packard Enterprise Development LP
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
#
##########################################################################

"""
OpenSwitch Test for vlan related configurations.
"""

from time import sleep
from pytest import mark
import pexpect

TOPOLOGY = """
# Nodes
[type=openswitch name="OpenSwitch 1"] ops1
[type=oobmhost image="host/freeradius-ubuntu:latest" name="Host 1"] hs1

# Ports
[force_name=oobm] ops1:sp1

# Links
ops1:sp1 -- hs1:if01
"""


sshclient = "/usr/bin/ssh -q -o UserKnownHostsFile=/dev/null" \
    "  -o StrictHostKeyChecking=no"

switches = []
hosts = []


def setupradiusserver(step):
    """ This function is to setup radius server in the ops-host image
    """
    h1 = hosts[0]
    switchip = getswitchip(step)
    print("SwitchIP:" + switchip)
    out = h1("sed -i \"76s/steve/netop/\" /etc/freeradius/users")
    out = h1("sed -i \"76s/#netop/netop/\" /etc/freeradius/users")
    out = h1("sed -i \"196s/192.168.0.0/"+switchip+"/\" "
             "/etc/freeradius/clients.conf")
    out = h1("sed -i \"196,199s/#//\" /etc/freeradius/clients.conf")

    h1("service freeradius stop")
    sleep(2)
    out = h1("service freeradius start")
    assert ("fail") not in out, "Failed to start freeradius on host"

    step("Configured radius server on host\n")


def setupradiusclient(step):
    """ This function is to setup radius client in the switch
    """
    s1 = switches[0]
    host_1_ipaddress = gethostip_1(step)
    print("Radius Server:" + host_1_ipaddress)
    s1("mkdir /etc/raddb/", shell="bash")
    s1("touch /etc/raddb/server", shell="bash")
    sleep(2)
    out = s1("configure terminal")
    assert "Unknown command" not in out, \
        "Failed to enter configuration terminal"

    sleep(2)
    s1("radius-server host " + host_1_ipaddress)
    s1("radius-server timeout 1")
    s1("radius-server retries 0")
    s1("exit")
    step("Configured radius client on switch\n")


def setupnet(step):
    setupradiusserver(step)
    setupradiusclient(step)


def getswitchip(step):
    """ This function is to get switch IP addess
    """
    s1 = switches[0]
    out = s1("ifconfig eth0", shell="bash")
    switchipaddress = out.split("\n")[1].split()[1][5:]
    return switchipaddress


def gethostip_1(step):
    """ This function is to get host IP addess
    """
    h1 = hosts[0]
    out = h1("ifconfig %s" % h1.ports["if01"])
    host_1_ipaddress = out.split("\n")[1].split()[1][5:]
    return host_1_ipaddress


def localauthenable(step):
    """ This function is to enable local authentication in DB
    with CLI command"""
    s1 = switches[0]
    out = ""
    out += s1("echo ", shell="bash")
    out = s1("configure terminal")
    assert "Unknown command" not in out, \
        "Failed to enter configuration terminal"

    out += s1("echo ", shell="bash")
    out = s1("aaa authentication login local")
    assert "Unknown command" not in out, \
        "Failed to enable local authentication"
    out += s1("echo ", shell="bash")
    s1("exit")
    return True


def radiusauthenable(step, chap=False):
    """ This function is to enable radius authentication in DB
    with CLI command"""
    s1 = switches[0]

    out = ""
    out += s1("echo ", shell="bash")
    out = s1("configure terminal")
    assert "Unknown command" not in out, \
        "Failed to enter configuration terminal"

    if chap:
        out += s1("echo ", shell="bash")
        out = s1("aaa authentication login radius radius-auth chap")
        assert "Unknown command" not in out, \
            "Failed to set chap for radius"
    else:
        out += s1("echo ", shell="bash")
        out = s1("aaa authentication login radius")
        assert "Unknown command" not in out, "Failed to enable radius " \
            "authentication"

    out += s1("echo ", shell="bash")
    s1("exit")
    return True


def nofallbackenable(step):
    """ This function is to disable fallback to local in DB
    with CLI command"""
    s1 = switches[0]

    out = ""
    out += s1("echo ", shell="bash")
    out = s1("configure terminal")
    assert "Unknown command" not in out, \
        "Failed to enter configuration terminal"

    out += s1("echo ", shell="bash")
    out = s1("no aaa authentication login fallback error local")
    assert "Unknown command" not in out, \
        "Failed to disable fallback to local authentication"

    out += s1("echo ", shell="bash")
    s1("exit")
    return True


def fallbackenable(step):
    """ This function is to enable fallback to local in DB
    with CLI command"""
    s1 = switches[0]

    out = ""
    out += s1("echo ", shell="bash")
    out = s1("configure terminal")
    assert "Unknown command" not in out, \
        "Failed to enter configuration terminal"

    out += s1("echo ", shell="bash")
    out = s1("aaa authentication login fallback error local")
    assert "Unknown command" not in out, "Failed to enable fallback to" \
        " local authentication"

    s1("exit")
    return True


def loginsshlocal(step):
    """This function is to verify local authentication is successful when
    radius is false and fallback is true"""
    step("########## Test to verify SSH login with local authenication "
         "enabled ##########\n")
    s1 = switches[0]
    ssh_newkey = "Are you sure you want to continue connecting"
    switchipaddress = getswitchip(step)
    step(".### switchIpAddress: " + switchipaddress + " ###\n")
    step(".### Running configuration ###\n")
    run = s1("show running-config")
    print(run)
    out = ""
    out += s1("echo ", shell="bash")
    myssh = sshclient + " netop@" + switchipaddress
    p = pexpect.spawn(myssh)

    i = p.expect([ssh_newkey, "password:", pexpect.EOF])

    if i == 0:
        p.sendline("yes")
        i = p.expect([ssh_newkey, "password:", pexpect.EOF])
    if i == 1:
        p.sendline("netop")
        j = p.expect(["#", "password:"])
        if j == 0:
            p.sendline("exit")
            p.kill(0)
            step(".### Passed SSH login with local credenticals ###\n")
            return True
        if j == 1:
            p.sendline("dummypassword")
            p.expect("password:")
            p.sendline("dummypasswordagain")
            p.kill(0)
            assert j != 1, "Failed to authenticate with local password"
    elif i == 2:
        assert i != 2, "Failed with SSH command"


def loginsshradius(step, chap=False):
    """This function is to verify radius authentication is successful when
    radius is true and fallback is false"""
    step("########## Test to verify SSH login with radius authentication "
         "enabled and fallback disabled ##########\n")
    s1 = switches[0]
    nofallbackenable(step)
    sleep(7)
    radiusauthenable(chap)
    sleep(7)
    ssh_newkey = "Are you sure you want to continue connecting"
    switchipaddress = getswitchip(step)
    step(".###switchIpAddress: " + switchipaddress + " ###\n")
    step(".### Running configuration ###\n")
    run = s1("show running-config")
    print(run)

    out = ""
    out += s1("echo ", shell="bash")
    myssh = sshclient + " netop@" + switchipaddress
    p = pexpect.spawn(myssh)

    i = p.expect([ssh_newkey, "password:", pexpect.EOF])

    if i == 0:
        p.sendline("yes")
        i = p.expect([ssh_newkey, "password:", pexpect.EOF])
    if i == 1:
        p.sendline("testing")
    elif i == 2:
        assert i != 2, "Failed with SSH command"
    loginpass = p.expect(["password:", "#"])
    if loginpass == 0:
        p.sendline("dummypassword")
        p.expect("password:")
        p.sendline("dummypasswordagain")
        p.kill(0)
        assert loginpass != 0, "Failed to login via radius authentication"
    if loginpass == 1:
        p.sendline("exit")
        p.kill(0)
        if chap:
            step(".### Passed SSH login with radius authentication and"
                 " chap ###\n")
        else:
            step(".### Passed SSH login with radius authentication ###\n")
        return True


def loginsshradiuswithfallback(step):
    """ This function is to verify radius authentication when fallback is
    enabled. Login with local password should work when raddius server is
    un reachable"""
    step("########## Test to verify SSH login with radius authenication"
         " enabled and fallback Enabled ##########\n")
    s1 = switches[0]
    h1 = hosts[0]
    fallbackenable(step)
    # checkAccessFiles()
    h1("service freeradius stop")

    ssh_newkey = "Are you sure you want to continue connecting"
    switchipaddress = getswitchip(step)
    step(".###switchIpAddress: " + switchipaddress + " ###\n")
    step(".### Running configuration ###\n")
    run = s1("show running-config")
    print(run)
    out = ""
    out += s1("echo ", shell="bash")
    myssh = sshclient + " netop@" + switchipaddress
    p = pexpect.spawn(myssh)

    i = p.expect([ssh_newkey, "password:", pexpect.EOF])

    if i == 0:
        p.sendline("yes")
        i = p.expect([ssh_newkey, "password:", pexpect.EOF])
    if i == 1:
        p.sendline("Testing")
    elif i == 2:
        assert i != 2, "Failed with SSH command"
    loginpass = p.expect(["password:", "#"])
    if loginpass == 0:
        p.sendline("netop")
        p.expect("#")
        p.sendline("exit")
        p.kill(0)
        step(".### Passed authentication with local password when radius"
             " server not reachable and fallback enabled ###\n")
        return True
    if loginpass == 1:
        p.sendline("exit")
        p.kill(0)
        assert loginpass != 1, "Failed to validate radius authetication" \
                               " when server is not reachable"


@mark.skipif(True, reason="will be enabled once RADIUS is stable")
@mark.platform_incompatible(['ostl'])
def test_aaa_ft_authentication(topology, step):
    global switches, hosts
    ops1 = topology.get('ops1')
    hs1 = topology.get('hs1')

    assert ops1 is not None
    assert hs1 is not None

    switches = [ops1]
    hosts = [hs1]

    ops1.name = "ops1"
    hs1.name = "hs1"

    setupnet(step)
    loginsshlocal(step)
    loginsshradius(step)
    loginsshradius(step, chap=True)
    loginsshradiuswithfallback(step)
