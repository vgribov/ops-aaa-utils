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

# from pytest import set_trace
# from time import sleep
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


def setradiusserverhost(dut):
    out = dut('configure terminal')
    assert 'Unknown command' not in out, \
        'Failed to enter configuration terminal'

    out = dut('radius-server host 192.168.1.5')
    assert 'Command failed' not in out, \
        'Failed to configure radius server'
    dut('end')

    out = dut('show radius-server')
    lines = out.splitlines()
    for line in lines:
        if 'Host IP address    : 192.168.1.5' in line:
            return True
    assert 'Host IP address\t: 192.168.1.5' in out, \
        'Test to configure the radius server host IP: Failed'


def setradiusservertimeout(dut):
    out = dut('configure terminal')
    assert 'Unknown command' not in out, \
        'Failed to enter configuration terminal'

    out = dut('radius-server host 192.168.1.5')
    out = dut('radius-server timeout 10')
    assert 'Command failed' not in out, \
        'Failed to configure radius timeout'
    dut('end')
    out = dut('show radius-server')
    lines = out.splitlines()
    for line in lines:
        if "Timeout        : 10" in line:
            return True
    assert 'Timeout\t\t: 10' in out, \
        'Test to configure radius server Timeout: Failed'


def setradiusserverretries(dut):
    out = dut('configure terminal')
    assert 'Unknown command' not in out, \
        'Failed to enter configuration terminal'

    out = dut('radius-server host 192.168.1.5')
    out = dut('radius-server retries 2')
    assert 'Command failed' not in out, \
        'Failed to configure radius retries'
    dut('end')
    out = dut('show radius-server')
    lines = out.splitlines()
    for line in lines:
        if "Retries        : 2" in line:
            return True

    assert 'Retries\t\t: 2' in out, \
        'Test to configure radius server Retries: Failed'


def setradiusauthport(dut):
    out = dut('configure terminal')
    assert 'Unknown command' not in out, \
        'Failed to enter configuration terminal'

    out = dut('radius-server host 192.168.1.5 auth-port 3333')
    assert 'Command failed' not in out, \
        'Failed to configure radius server authentication port'
    dut('end')
    out = dut('show radius-server')
    lines = out.splitlines()
    for line in lines:
        if "Auth port        : 3333" in line:
            return True

    assert 'Auth port\t\t: 3333' in out, \
        'Test to configure radius server Authentication port: Failed'


def setradiuspasskey(dut):
    out = dut('configure terminal')
    assert 'Unknown command' not in out, \
        'Failed to enter configuration terminal'

    out = dut('radius-server host 192.168.1.5 key myhost')
    assert 'Command failed' not in out, \
        'Failed to configure radius-server host passkey'
    dut('end')
    out = dut('show radius-server')
    lines = out.splitlines()
    for line in lines:
        if "Shared secret        : myhost" in line:
            return True

    assert 'Shared secret\t\t: myhost' in out, \
        'Test to configure radius server Passkey: Failed'


def noradiuspassky(dut):
    out = dut('configure terminal')
    assert 'Unknown command' not in out, \
        'Failed to enter configuration terminal'

    out = dut('radius-server host 192.168.1.5 key myhost')
    out = dut('no radius-server host 192.168.1.5 key myhost')
    assert 'Command failed' not in out, \
        'Failed to configure no radius-server passkey'
    dut('end')
    out = dut('show radius-server')
    lines = out.splitlines()
    for line in lines:
        if 'Host IP address\t: 192.168.1.5' in line:
            for line in lines:
                return True

    assert 'Host IP address\t: 192.168.1.5' in out, \
         'Test to remove radius server Passkey and reset to default: Failed'


def noradiusauthport(dut):
    out = dut('configure terminal')
    assert 'Unknown command' not in out, \
        'Failed to enter configuration terminal'

    out = dut('radius-server host 192.168.1.5 auth-port 3333')
    out = dut('no radius-server host 192.168.1.5 auth-port 3333')
    assert 'Command failed' not in out, \
        'Failed to configure no radius-server auth port'
    dut('end')
    out = dut('show radius-server')
    lines = out.splitlines()
    for line in lines:
        if 'Host IP address\t: 192.168.1.5' in line:
            for line in lines:
                if "Auth port        : 1812" in line:
                    return True
    assert 'Host IP address\t: 192.168.1.5' in out, \
        'Test to remove radius server Authentication port and reset \
         to default: Failed'


def noradiustimeout(dut):
    out = dut('configure terminal')
    assert 'Unknown command' not in out, \
        'Failed to enter configuration terminal'

    out = dut('radius-server host 192.168.1.5')
    out = dut('radius-server timeout 10')
    out = dut('no radius-server timeout 10')
    assert 'Command failed' not in out, \
        'Failed to configure no radius-server timeout'
    dut('end')
    out = dut('show radius-server')
    lines = out.splitlines()
    for line in lines:
        if "Timeout        : 5" in line:
            return True
    assert 'Timeout\t\t: 5' in out, \
        'Test to remove radius server timeout and reset to default: Failed'


def noradiusretries(dut):
    out = dut('configure terminal')
    assert 'Unknown command' not in out, \
        'Failed to enter configuration terminal'

    out = dut('radius-server host 192.168.1.5')
    out = dut('radius-server retries 2')
    out = dut('no radius-server retries 2')
    assert 'Command failed' not in out, \
        'Failed to configure no radius-server retries'
    dut('end')
    out = dut('show radius-server')
    lines = out.splitlines()
    for line in lines:
        if "Retries        : 1" in line:
            return True
    assert 'Retries\t\t: 1' in out, \
        'Test to remove radius server Retries and reset to default: Failed'


@mark.gate
def test_vtysh_ct_aaa(topology, step):
    ops1 = topology.get('ops1')
    assert ops1 is not None

    step('Test to enable SSH password authentication')
    enablepasskeyauth(ops1)

    step('Test to disable SSH password authentication')
    disablepasskeyauth(ops1)

    step('Test to enable SSH public key authentication')
    enablepublickeyauth(ops1)

    step('Test to disable SSH public key authentication')
    disablepublickeyauth(ops1)

    step('Test to configure the radius server host IP')
    setradiusserverhost(ops1)

    step('Test to configure radius server Timeout')
    setradiusservertimeout(ops1)

    step('Test to configure radius server Retries')
    setradiusserverretries(ops1)

    step('Test to configure radius server Authentication port')
    setradiusauthport(ops1)

    step('Test to configure radius server Passkey')
    setradiuspasskey(ops1)

    step('Test to remove radius server Passkey and reset to default')
    noradiuspassky(ops1)

    step('Test to remove radius server Authentication port and reset to'
         ' default')
    noradiusauthport(ops1)

    step('Test to remove radius server timeout and reset to default')
    noradiustimeout(ops1)

    step('Test to remove radius server Retries and reset to default')
    noradiusretries(ops1)
