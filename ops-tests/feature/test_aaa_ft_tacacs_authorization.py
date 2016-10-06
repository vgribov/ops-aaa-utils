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

NETOP_PTIV_LVL = "14"

def tacacs_add_server(dut, step):
    step('\n### === Adding tacacs server === ###')
    vtysh_shell = dut.get_shell('vtysh')
    matches = ['#']
    cmd = "su netop"
    assert vtysh_shell.send_command(cmd, matches) is 0
    # dut("su netop", shell='bash')
    dut("configure terminal")
    dut("tacacs-server host 192.168.1.254")
    dut("tacacs-server host 192.168.1.253")
    dut("end")
    dump = dut("show running-config")
    lines = dump.splitlines()
    count = 0

    for line in lines:
        if "tacacs-server host 192.168.1.254" in line:
           count = count + 1
        if "tacacs-server host 192.168.1.253" in line:
           count = count + 1
    assert count == 2,\
           '\n### Adding tacacs servers test failed ###'
    step('\n### servers present in running config - passed ###')
    step('\n### === server added == ###\n')


def tacacs_create_server_group(dut, step):
    step('\n### === Create tacacs+ group tac1, tac2 and add server === ###')
    dut("configure terminal")
    dut("aaa group server tacacs_plus tac1")
    dut("server 192.168.1.254")
    dut("exit")
    dut("aaa group server tacacs_plus tac2")
    dut("server 192.168.1.253")
    dut("end")

    count = 0
    dump = dut("show running-config")
    lines = dump.splitlines()

    for line in lines:
        if "aaa group server tacacs+ tac1" in line:
            count = count + 1
        if "server 192.168.1.254" in line:
            count = count + 1
        if "aaa group server tacacs+ tac2" in line:
            count = count + 1
        if "server 192.168.1.253" in line:
            count = count + 1
    assert count == 4,\
            '\n### Create tacacs+ group tac1,tac2 and add server test failed ###'

    step('\n### Create tacacs+ group tac1,tac2 and add server test passed ###')
    step('\n### === Create tacacs+ group tac1,tac2 and add server test end === ###\n')


def set_aaa_authorization_none(dut, step):
    step('\n### === set aaa authorization to none test start === ###')
    dut("configure terminal")
    dut("aaa authorization commands default none")
    dut("end")

    count = 0
    ''' now check the running config '''
    dump = dut("show running-config")
    lines = dump.splitlines()
    for line in lines:
        if ("aaa authorization commands default none" in line):
            count = count + 1
    assert count == 1,\
            '\n### set aaa authorization to none test failed ###'

    step('\n### set aaa authorization to none test passed ###')
    step('\n### === set aaa authorization to none test end === ###\n')


def set_aaa_authorization_groups_chk_authorization(dut, step):
    step('\n### === set aaa authorization with groups test start === ###')
    dut("configure terminal")
    dut("aaa authorization commands default group tac1 tac2 none")
    dut("end")

    count = 0
    ''' now check the running config '''
    dump = dut("show running-config")
    lines = dump.splitlines()
    for line in lines:
        if ("aaa authorization commands default group tac1 tac2 none" in line):
            count = count + 1
    assert count == 1,\
            '\n### set aaa authorization with groups and test authorization test failed ###'

    step('\n### set aaa authorization with groups and test authorization test passed ###')
    step('\n### === set aaa authorization with groups and test authorization test end === ###\n')


def unset_aaa_authentication_groups(dut, step):
    step('\n### === unset aaa authorization test start === ###')
    dut("configure terminal")
    dut("no aaa authorization commands default")
    dut("end")

    count = 0
    ''' now check the running config '''
    dump = dut("show running-config")
    lines = dump.splitlines()
    for line in lines:
        if ("aaa authorization commands default" in line):
            count = count + 1
    assert count == 0,\
            '\n### unset aaa authorization test failed ###'

    step('\n### unset aaa authorization  test passed ###')
    step('\n### === unset aaa authorization test end === ###\n')


@mark.skipif(True, reason="Disabling as AAA feature revamp in progress")
def test_ct_tacacs_config(topology, step):
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

    tacacs_add_server(ops1, step)

    tacacs_create_server_group(ops1, step)

    set_aaa_authorization_none(ops1, step)

    set_aaa_authorization_groups_chk_authorization(ops1, step)
