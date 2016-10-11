# (c) Copyright 2016 Hewlett Packard Enterprise Development LP
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

from time import sleep
from pytest import mark


TOPOLOGY = """
# +--------+         +--------+
# |        |eth0     |        |
# |  hs2   +---------+  ops1  |
# |        |     eth1|        |
# +--------+         +-+------+
#                      |eth0
#                      |
#                      |eth0
#                  +---+----+
#                  |        |
#                  |  hs1   |
#                  |        |
#                  +--------+

# Nodes
[type=openswitch name="OpenSwitch 1"] ops1
[type=oobmhost image="openswitch/tacacs_server:latest" name="Host 1"] hs1
[type=oobmhost image="openswitch/tacacs_server:latest" name="Host 2"] hs2

# Ports
[force_name=oobm] ops1:eth1
[force_name=oobm] ops1:eth0

# Links
ops1:eth0 -- hs1:eth0
ops1:eth1 -- hs2:eth0
"""

USER1 = "user1"
USER1_PASSWD = "user1"
NETOP = "netop"
NETOP_PASS = "netop"

def tacacs_authentication_and_authorization_configuration(hs1, user, pwd, step):

    step('\n### === Running: Add tacacs+ servers === ###\n')
    ssh_cmd = "ssh -o StrictHostKeyChecking=no " + user + \
        "@192.168.1.1"
    matches = ['password:']
    shell = hs1.get_shell('bash')
    assert shell.send_command(ssh_cmd, matches) is 0
    matches = ['#']
    assert shell.send_command(pwd, matches) is 0, "ssh" \
        " as new user failed."
    shell.send_command("show privilege-level", matches=["#"])
    shell.send_command("configure terminal", matches=["#"])
    shell.send_command("tacacs-server host 192.168.1.254 key tac_test", matches=["#"])
    shell.send_command("tacacs-server host 192.168.1.253 key tac_test", matches=["#"])
    shell.send_command("end", matches=["#"])
    shell.send_command("show running-config", matches=["#"])
    result = shell.get_response()
    assert "tacacs-server host 192.168.1.254" and \
           "tacacs-server host 192.168.1.253" in result, \
           '\n### Adding tacacs servers test failed ###'

    step('\n### Add tacacs+ servers: success ###\n')


    step('\n### === Running: Create tacacs_plus group tac1, tac2 === ###\n')

    shell.send_command("configure terminal", matches=["#"])
    shell.send_command("aaa group server tacacs_plus tac1", matches=["#"])
    shell.send_command("server 192.168.1.254", matches=["#"])
    shell.send_command("exit", matches=["#"])
    shell.send_command("aaa group server tacacs_plus tac2", matches=["#"])
    shell.send_command("server 192.168.1.253", matches=["#"])
    shell.send_command("end", matches=["#"])

    count = 0
    ''' now check the running config '''
    shell.send_command("show running-config", matches=["#"])
    dump = shell.get_response()
    lines = dump.splitlines()
    for line in lines:
        if "aaa group server tacacs_plus tac1" in line:
            count = count + 1
        if "server 192.168.1.254" in line:
            count = count + 1
        if "aaa group server tacacs_plus tac2" in line:
            count = count + 1
        if "server 192.168.1.253" in line:
            count = count + 1
    assert count == 4,\
            '\n### Create tacacs_plus group tac1,tac2 and add server test failed ###'

    step('\n### Create tacacs_plus group tac1,tac2 : success ###\n')

    step('\n### === Running : Set tacacs+ authentication with groups so that remote user can login === ###\n')

    shell.send_command("configure terminal", matches=["#"])
    shell.send_command("aaa authentication login default group tac2 local", matches=["#"])
    shell.send_command("end", matches=["#"])

    count = 0
    ''' now check the running config '''
    shell.send_command("show running-config", matches=["#"])
    dump = shell.get_response()
    lines = dump.splitlines()
    for line in lines:
        if ("aaa authentication login default group tac2 local" in line):
            count = count + 1
    assert count == 1,\
            '\n### set aaa authentication with groups test failed ###'

    step('\n###  set aaa authentication with groups so that remote user can login: success ###\n')

    step('\n### === Running : Set none as tacacs+ command authorization and test command authorization === ###\n')

    shell.send_command("configure terminal", matches=["#"])
    shell.send_command("aaa authorization commands default none", matches=["#"])
    shell.send_command("end", matches=["#"])

    count = 0
    ''' now check the running config '''
    shell.send_command("show running-config", matches=["#"])
    dump = shell.get_response()
    lines = dump.splitlines()
    for line in lines:
        if ("aaa authorization commands default none" in line):
            count = count + 1
    assert count == 1,\
            '\n### set aaa authorization to none test failed ###'

    step('\n### Test 1 : Set none as tacacs+ command authorization and test command authorization : Success ###\n')

    step('\n### === Running: Set tacacs+ groups and none as tacacs cmd authorization and test tacacs command authorization as local user=== ###\n')

    shell.send_command("configure terminal", matches=["#"])
    shell.send_command("aaa authorization commands default group tac1 tac2", matches=["#"])
    shell.send_command("end", matches=["#"])

    count = 0
    ''' now check the running config '''
    shell.send_command("show running-config", matches=["#"])
    dump = shell.get_response()
    lines = dump.splitlines()
    for line in lines:
        if ("aaa authorization commands default group tac1 tac2" in line):
            count = count + 1
    assert count == 1,\
            '\n### set aaa authorization with groups and test tacacs authorization as local user test failed ###'

    step('\n### Test 2: set aaa authorization with groups and test tacacs authorization as local user: success ###\n')

    shell.send_command("exit", matches=["Connection to 192.168.1.1 closed"])

def set_unreachable_servers_and_test_cmd_author(hs1, user, pwd, step):
    step('\n### === Running : set unreachable tacacs+ server and test cmd authorization === ###\n')
    ssh_cmd = "ssh -o StrictHostKeyChecking=no " + user + \
        "@192.168.1.1"
    matches = ['password:']
    shell = hs1.get_shell('bash')
    assert shell.send_command(ssh_cmd, matches) is 0
    matches = ['#']
    assert shell.send_command(pwd, matches) is 0, "ssh" \
        " as new user failed."

    shell.send_command("configure terminal", matches=["#"])
    shell.send_command("tacacs-server host 1.1.1.1 key tac_test", matches=["#"])
    shell.send_command("aaa group server tacacs_plus tac3", matches=["#"])
    shell.send_command("server 1.1.1.1", matches=["#"])
    shell.send_command("exit", matches=["#"])
    shell.send_command("aaa authorization commands default group tac3", matches=["#"])
    shell.send_command("end", matches=["#"])

    count = 0
    ''' now check the running config '''
    shell.send_command("show running-config", matches=["#"])
    dump =  shell.get_response()
    lines = dump.splitlines()
    for line in lines:
        if ("Cannot execute command. Could not connect to any TACACS+ servers." in line):
            count = count + 1
    assert count == 1,\
           '\n ### Failed to verify unreachable tacacs server test ###\n'

    step('\n### Test4: set unreachable tacacs+ server for tacacs+ cmd authorization and test cmd authorization: success ###\n')


def ssh_as_tacacs_remote_user_and_test_tacacs_cmd_authorization(step, hs1, user, pwd):
    step("### === Running : ssh to switch as a remote tacacs+ user and test command authorization === ###\n")

    ssh_cmd = "ssh -o StrictHostKeyChecking=no " + user + \
        "@192.168.1.1"
    matches = ['password:']
    bash_shell = hs1.get_shell('bash')
    assert bash_shell.send_command(ssh_cmd, matches) is 0
    matches = ['#']
    assert bash_shell.send_command(pwd, matches) is 0, "ssh" \
        " as new user failed."
    cmd = "show run"
    matches = ['Cannot execute command. Command not allowed.']
    assert bash_shell.send_command(cmd, matches) is 0, "### Login as unauthorized user" \
        " and test command authorization failed ###"

    step('\n### Test3: ssh to switch as a remote tacacs+ user and test command authorization: success ###\n')

    bash_shell.send_command("exit", matches=["Connection to 192.168.1.1 closed"])

def start_tacacs_service(step, host):
    step("#### Running : start tac_plus daemon on the server ####\n")
    host("service tac_plus start")
    sleep(5)
    out = host("ps -ef | grep tac_plus")
    assert ("/usr/bin/tac_plus -C /etc/tacacs/tac_plus.conf") in out, "Failed to start tac_plus on the host"
    step("### Started tacacs service on the tacacs server ###\n")


@mark.skipif(True, reason="framework/infra issue when ssh to the switch")
def test_tacacs_cmd_authorization_feature(topology, step):
    ops1 = topology.get('ops1')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    # Wait switch to come up
    sleep(10)

    # Server IP address
    hs1.libs.ip.interface('eth0', addr='192.168.1.254/24', up=True)

    hs2.libs.ip.interface('eth0', addr='192.168.1.253/24', up=True)

    # Switch IP address
    with ops1.libs.vtysh.ConfigInterfaceMgmt() as ctx:
        ctx.ip_static('192.168.1.1/24')

    start_tacacs_service(step, hs1)
    start_tacacs_service(step, hs2)

    tacacs_authentication_and_authorization_configuration(hs1, NETOP, NETOP_PASS, step)

    ssh_as_tacacs_remote_user_and_test_tacacs_cmd_authorization(step, hs1, USER1, USER1_PASSWD)

    set_unreachable_servers_and_test_cmd_author(hs1, NETOP, NETOP_PASS, step)

    step("\n\n### !!! All the tests for tacacs command authorization passed !!! ####\n")
