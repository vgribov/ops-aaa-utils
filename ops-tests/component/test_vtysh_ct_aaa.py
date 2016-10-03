# -*- coding: utf-8 -*-
# (C) Copyright 2015-2016 Hewlett Packard Enterprise Development LP
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
OpenSwitch Test for switchd related configurations.
"""
from pytest import mark

from pytest import mark

TOPOLOGY = """
# +-------+
# |  ops1 |
# +-------+

# Nodes
[type=openswitch name="OpenSwitch 1"] ops1
"""


def enablepasskeyauth(dut):
    ''' This function is to enable passkey authentication for
    SSH authentication method'''

    out = dut('configure terminal')
    assert 'Unknown command' not in out

    out = dut('ssh password-authentication')
    assert 'Command failed' not in out

    dut('end')

    out = dut('cat /etc/ssh/sshd_config', shell='bash')
    lines = out.splitlines()
    for line in lines:
        if 'PasswordAuthentication yes' in line:
            return True
    assert 'PasswordAuthentication yes' in out, \
        'Failed to enable password authentication'


def disablepasskeyauth(dut):
    ''' This function is to enable passkey authentication for
    SSH authentication method'''

    out = dut('configure terminal')
    assert 'Unknown command' not in out, \
        'Failed to enter configuration terminal'

    out = dut('no ssh password-authentication')
    assert 'Command failed' not in out, \
        'Failed to execute no ssh password authentication command'

    dut('end')

    out = dut('cat /etc/ssh/sshd_config', shell='bash')
    lines = out.splitlines()
    for line in lines:
        if 'PasswordAuthentication no' in line:
            return True
    assert 'PasswordAuthentication no' in out, \
        'Failed to disable password key authentication'


def enablepublickeyauth(dut):
    ''' This function is to enable passkey authentication for
    SSH authentication method'''

    out = dut('configure terminal')
    assert 'Unknown command' not in out, \
        'Failed to enter configuration terminal'

    out = dut('ssh public-key-authentication')
    assert 'Command failed' not in out, \
        'Failed to execute ssh public-key authentication command'

    dut('end')

    out = dut('cat /etc/ssh/sshd_config', shell='bash')
    lines = out.splitlines()
    for line in lines:
        if 'PubkeyAuthentication yes' in line:
            return True
    assert 'PubkeyAuthentication yes' in out, \
        'Failed to enable public key authentication'


def disablepublickeyauth(dut):
    ''' This function is to enable passkey authentication for
    SSH authentication method'''

    out = dut('configure terminal')
    assert 'Unknown command' not in out, \
        'Failed to enter configuration terminal'

    out = dut('no ssh public-key-authentication')
    assert 'Command failed' not in out, \
        'Failed to execute ssh no public-key authentication command'

    dut('end')

    out = dut('cat /etc/ssh/sshd_config', shell='bash')
    lines = out.splitlines()
    for line in lines:
        if 'PubkeyAuthentication no' in line:
            return True
    assert 'PubkeyAuthentication no' in out, \
        'Failed to disable public key authentication'

def enable_fail_through(dut):
    dut('configure terminal')
    dut('aaa authentication allow-fail-through')
    dut('end')
    out = dut('show running-config')
    lines = out.splitlines()
    count = 0
    for line in lines:
        if "aaa authentication allow-fail-through" in line:
            count = count + 1

    out = dut('show aaa authentication')
    lines = out.splitlines()
    for line in lines:
        if "Fail-through\t\t\t\t: Enabled" in line:
            count = count + 1

    assert count == 2, \
            'Test to enable fail-through : Failed'

def disable_fail_through(dut):
    dut('configure terminal')
    dut('no aaa authentication allow-fail-through')
    dut('end')
    out = dut('show aaa authentication')
    lines = out.splitlines()

    count = 0
    for line in lines:
        if "Fail-through\t\t\t\t: Disabled" in line:
            count = count + 1

    assert count == 1, \
            'Test to disable fail-through : Failed'

    count = 0
    out = dut('show running-config')
    lines = out.splitlines()
    for line in lines:
        if "aaa authentication allow-fail-through" in line:
            count = count + 1
    assert count == 0, \
            'Test to disable fail-through : Failed'

@mark.gate
def test_vtysh_ct_aaa(topology, step):
    ops1 = topology.get('ops1')
    assert ops1 is not None

    step('Test to enable SSH password authentication')
    enablepasskeyauth(ops1)

    step('Test to disable SSH password authentication')
    disablepasskeyauth(ops1)

    step('Test to enable fail-through')
    enable_fail_through(ops1)

    step('Test to disable fail-through')
    disable_fail_through(ops1)

    step('Test to enable SSH public key authentication')
    enablepublickeyauth(ops1)

    step('Test to disable SSH public key authentication')
    disablepublickeyauth(ops1)
