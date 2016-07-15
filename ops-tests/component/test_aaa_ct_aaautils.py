# Copyright (C) 2016 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

import pexpect
from time import sleep

TOPOLOGY = """
# +-------+                   +-------+
# |       |     +-------+     |       |
# |  hs1  <----->  sw1  <----->  hs2  |
# |       |     +-------+     |       |
# +-------+                   +-------+

# Nodes
[type=openswitch name="Switch 1"] sw1
[type=oobmhost image="host/freeradius-ubuntu:latest" name="Host 1"] h1
[type=oobmhost image="host/freeradius-ubuntu:latest" name="Host 2"] h2

# Ports
[force_name=oobm] sw1:sp1
[force_name=oobm] sw1:sp2

# Links
h1:if01 -- sw1:sp1
sw1:sp2 -- h2:if01
"""

SSHCLIENT = "/usr/bin/ssh -o UserKnownHostsFile=/dev/null" \
    "  -o StrictHostKeyChecking=no"


def setupradiusserver(h1, h2, sw1):
    ''' This function is to setup radius server in the ops-host image '''
    switchip = getswitchip(sw1)
    out = h1("sed -i '76s/steve/netop/' /etc/freeradius/users")
    out = h1("sed -i '76s/#netop/netop/' /etc/freeradius/users")
    out = h1("sed -i '196s/192.168.0.0/" + switchip + "/' "
             "/etc/freeradius/clients.conf")
    out = h1("sed -i '196,199s/#//' /etc/freeradius/clients.conf")

    h1("service freeradius stop")
    sleep(1)
    out = h1("service freeradius start")

    out = h2("sed -i '76s/steve/netop/' /etc/freeradius/users")
    out = h2("sed -i '76s/#netop/netop/' /etc/freeradius/users")
    out = h2("sed -i '196s/192.168.0.0/" + switchip + "/' "
             " /etc/freeradius/clients.conf")
    out = h2("sed -i '196,199s/#//' /etc/freeradius/clients.conf")

    out = h2("service freeradius stop")
    print(out)
    sleep(1)
    h2("service freeradius start")
    print('Configured radius server on host\n')


def setupradiusclient(h1, h2, sw1):
    ''' This function is to setup radius client in the switch '''
    host_1_ipaddress = gethostip_1(h1)
    host_2_ipaddress = gethostip_2(h2)
    sw1("mkdir /etc/raddb/", shell="bash")
    sw1("touch /etc/raddb/server", shell="bash")
    sleep(1)
    sw1("configure terminal")

    sleep(1)
    sw1("radius-server host " + host_1_ipaddress)
    sw1("radius-server host " + host_2_ipaddress)
    sw1("radius-server timeout 1")
    sw1("radius-server retries 0")
    sw1("end")
    print('Configured radius client on switch\n')


def setupnet(h1, h2, sw1):
    # Create a topology with single Openswitch and two host.

    # Select ops-host image from docker hub, which has freeradius installed.

    setupradiusserver(h1, h2, sw1)
    setupradiusclient(h1, h2, sw1)


def getswitchip(sw1):
    ''' This function is to get switch IP addess '''
    out = sw1("ifconfig eth0", shell="bash")
    switchipaddress = out.split("\n")[1].split()[1][5:]
    return switchipaddress


def gethostip_1(h1):
    ''' This function is to get host IP addess '''
    out = h1("ifconfig eth0")
    host_1_ipaddress = out.split("\n")[1].split()[1][5:]
    return host_1_ipaddress


def gethostip_2(h2):
    ''' This function is to get host IP addess '''
    out = h2("ifconfig eth0")
    host_2_ipaddress = out.split("\n")[1].split()[1][5:]
    return host_2_ipaddress


# Call checkAccessFiles to verify if configurations files are modified
# Update caller functions in test cases to debug.
def checkaccessfiles(sw1):
    '''This function is to check if /etc/pam.d/common-*-access are modified
    based on the change in DB by cli '''
    out = sw1("cat /etc/pam.d/common-auth-access", shell="bash")
    lines = out.split('\n')
    for line in lines:
        if "auth" in line:
            print(line)
    print('\n')
    sleep(0.25)
    out = sw1("cat /etc/pam.d/common-account-access", shell="bash")
    lines = out.split('\n')
    for line in lines:
        if "account" in line:
            print(line)
    print('\n')
    sleep(0.25)
    out = sw1("cat /etc/pam.d/common-password-access", shell="bash")
    lines = out.split('\n')
    for line in lines:
        if "password" in line:
            print(line)
    print('\n')
    sleep(0.25)
    out = sw1("cat /etc/pam.d/common-session-access", shell="bash")
    lines = out.split('\n')
    for line in lines:
        if "session" in line:
            print(line)
    print('\n')


def localauthenable(sw1):
    ''' This function is to enable local authentication in DB
    with CLI command'''

    out = sw1("configure terminal")
    out = sw1("aaa authentication login local")
    assert 'Unknown command' not in out, \
        "Failed to enable local authentication"
    sw1("end")
    return True


def radiusauthenable(sw1):
    ''' This function is to enable radius authentication in DB
    with CLI command'''

    out = sw1("configure terminal")
    out = sw1("aaa authentication login radius")
    assert 'Unknown command' not in out, \
        "Failed to enable radius authentication"
    sw1("end")
    return True


def nofallbackenable(sw1):
    ''' This function is to disable fallback to local in DB
    with CLI command'''

    out = sw1("configure terminal")
    out = sw1("no aaa authentication login fallback error local")
    assert 'Unknown command' not in out, \
        "Failed to disable fallback to local authentication"

    sw1("end")
    return True


def fallbackenable(sw1):
    ''' This function is to enable fallback to local in DB
    with CLI command'''

    out = sw1("configure terminal")
    out = sw1("aaa authentication login fallback error local")
    assert 'Unknown command' not in out, \
        "Failed to enable fallback to local authentication"

    sw1("end")
    return True


def loginsshlocal(sw1):
    '''This function is to verify local authentication is successful when
    radius is false and fallback is true'''
    print('########## Test to verify SSH login with local authenication '
          'enabled ##########\n')
    ssh_newkey = 'Are you sure you want to continue connecting'
    switchipaddress = getswitchip(sw1)
    myssh = SSHCLIENT + " netop@" + switchipaddress

    p = pexpect.spawn(myssh)

    i = p.expect([ssh_newkey, 'password:', pexpect.EOF])

    if i == 0:
        p.sendline('yes')
        i = p.expect([ssh_newkey, 'password:', pexpect.EOF])
    if i == 1:
        p.sendline('netop')
        j = p.expect(['#', 'password:'])
        if j == 0:
            p.sendline('end')
            p.kill(0)
            print(".### Passed SSH login with local credenticals ###\n")
            return True
        if j == 1:
            p.sendline('dummypassword')
            p.expect('password:')
            p.sendline('dummypasswordagain')
            p.kill(0)
            assert j != 1, "Failed to authenticate with local password"
    elif i == 2:
        assert i != 2, "Failed with SSH command"


def loginsshradius(sw1):
    '''This function is to verify radius authentication is successful when
    radius is true and fallback is false'''
    print('########## Test to verify SSH login with radius authenication '
          'enabled and fallback disabled ##########\n')
    nofallbackenable(sw1)
    sleep(5)
    radiusauthenable(sw1)
    sleep(5)
    ssh_newkey = 'Are you sure you want to continue connecting'
    switchipaddress = getswitchip(sw1)
    out = ""
    out += sw1("echo ", shell="bash")
    myssh = SSHCLIENT + " netop@" + switchipaddress
    p = pexpect.spawn(myssh)

    i = p.expect([ssh_newkey, 'password:', pexpect.EOF])

    if i == 0:
        p.sendline('yes')
        i = p.expect([ssh_newkey, 'password:', pexpect.EOF])
    if i == 1:
        p.sendline('testing')
    elif i == 2:
        assert i != 2, "Failed with SSH command"
    loginpass = p.expect(['password:', '#'])
    if loginpass == 0:
        p.sendline('dummypassword')
        p.expect('password:')
        p.sendline('dummypasswordagain')
        p.kill(0)
        assert loginpass != 0, "Failed to login via radius authentication"
    if loginpass == 1:
        p.sendline('end')
        p.kill(0)
        print(".### Passed SSH login with radius authentication ###\n")
        return True


def loginsshradiuswithlocalpassword(sw1):
    ''' This is a negative test case to verify login with radius
    authentication by giving loca password'''
    print('########## Test to verify SSH login with radius authenication '
          'enabled and fallback disabled and using local password #########\n')
    ssh_newkey = 'Are you sure you want to continue connecting'
    switchipaddress = getswitchip(sw1)
    out = ""
    out += sw1("echo ", shell="bash")
    myssh = SSHCLIENT + " netop@" + switchipaddress
    p = pexpect.spawn(myssh)

    i = p.expect([ssh_newkey, 'password:', pexpect.EOF])

    if i == 0:
        p.sendline('yes')
        i = p.expect([ssh_newkey, 'password:', pexpect.EOF])
    if i == 1:
        p.sendline('netop')
    elif i == 2:
        assert i != 2, "Failed with SSH command"
    loginpass = p.expect(['password:', '#'])
    if loginpass == 0:
        p.sendline('netop')
        p.expect('password:')
        p.sendline('netop')
        p.expect('Permission denied')
        p.kill(0)
        print(".### Passed negative test - Authentication fail with local"
              " password when radius server authentication enabled ###\n")
        return True
    if loginpass == 1:
        p.sendline('end')
        p.kill(0)
        assert loginpass != 1, "Failed to validate radius authetication" \
                               " with local password"


def loginsshradiuswithfallback(h1, h2, sw1):
    ''' This function is to verify radius authentication when fallback is
    enabled. Login with local password should work when raddius server is
    un reachable'''
    print('########## Test to verify SSH login with radius authenication'
          ' enabled and fallback Enabled ##########\n')
    fallbackenable(sw1)
    host_2_ipaddress = gethostip_2(h2)
    sw1("configure terminal")
    sw1("no radius-server host " + host_2_ipaddress)
    h1("service freeradius stop")
    h2("service freeradius stop")

    ssh_newkey = 'Are you sure you want to continue connecting'
    switchipaddress = getswitchip(sw1)
    out = ""
    out += sw1("echo ", shell="bash")
    myssh = SSHCLIENT + " netop@" + switchipaddress
    p = pexpect.spawn(myssh)

    i = p.expect([ssh_newkey, 'password:', pexpect.EOF])

    if i == 0:
        p.sendline('yes')
        i = p.expect([ssh_newkey, 'password:', pexpect.EOF])
    if i == 1:
        p.sendline('Testing')
    elif i == 2:
        assert i != 2, "Failed with SSH command"
    loginpass = p.expect(['password:', '#'])
    if loginpass == 0:
        p.sendline('netop')
        p.expect('#')
        p.sendline('end')
        p.kill(0)
        sw1("radius-server host " + host_2_ipaddress)
        sw1("end")
        print(".### Passed authentication with local password when radius"
              " server not reachable and fallback enabled ###\n")
        return True
    if loginpass == 1:
        p.sendline('end')
        p.kill(0)
        sw1("radius-server host " + host_2_ipaddress)
        sw1("end")
        assert loginpass != 1, "Failed to validate radius authetication" \
                               " when server is not reachable"


def loginsshlocalwrongpassword(sw1):
    ''' This is a negative test case, enable only local authetication
    and try logging with wrong password'''
    print('########## Test to verify SSH login with local authenication'
          ' enabled and Wrong password ##########\n')
    nofallbackenable(sw1)
    sleep(5)
    localauthenable(sw1)
    sleep(5)
    ssh_newkey = 'Are you sure you want to continue connecting'
    switchipaddress = getswitchip(sw1)
    out = ""
    out += sw1("echo ", shell="bash")
    myssh = SSHCLIENT + " netop@" + switchipaddress
    p = pexpect.spawn(myssh)

    i = p.expect([ssh_newkey, 'password:', pexpect.EOF])

    if i == 0:
        p.sendline('yes')
        i = p.expect([ssh_newkey, 'password:', pexpect.EOF])
    if i == 1:
        p.sendline('netop1')
    elif i == 2:
        assert i != 2, "Failed with SSH command"
    loginpass = p.expect(['password:', '#'])
    if loginpass == 0:
        p.sendline('netop2')
        p.expect('password:')
        p.sendline('netop3')
        p.expect('Permission denied')
        p.kill(0)
        print(".### Passed negative test - Authentication fail with wrong"
              " local password when local authentication enabled ###\n")
        return True
    if loginpass == 1:
        p.sendline('end')
        p.kill(0)
        assert loginpass != 1, "Failed to validate local authentication"


def loginsshlocalagain(sw1):
    ''' This is again a test case to verify, when local authetication is
    enabled login should properly work with local password'''
    print('########## Test to verify SSH login with local authenication'
          ' enabled again with correct password ##########\n')
    ssh_newkey = 'Are you sure you want to continue connecting'
    switchipaddress = getswitchip(sw1)
    out = ""
    out += sw1("echo ", shell="bash")
    myssh = SSHCLIENT + " netop@" + switchipaddress
    p = pexpect.spawn(myssh)

    i = p.expect([ssh_newkey, 'password:', pexpect.EOF])

    if i == 0:
        p.sendline('yes')
        i = p.expect([ssh_newkey, 'password:', pexpect.EOF])
    if i == 1:
        p.sendline('netop')
    elif i == 2:
        assert i != 2, "Failed with SSH command"
    loginpass = p.expect(['password:', '#'])
    if loginpass == 0:
        p.sendline('netop2')
        p.expect('password:')
        p.sendline('netop3')
        p.expect('Permission denied')
        p.kill(0)
        assert loginpass != 0, "Failed to validate local authentication" \
                               " with correct password"
    if loginpass == 1:
        p.sendline('end')
        p.kill(0)
        print(".### Passed authentication with local password when local"
              " authentication enabled ###\n")
        return True


def loginsshradiuswithsecondaryserver(h1, h2, sw1):
    '''This function is to verify radius authentication with the secondary
    radius server when unable to reach primary server - radius is true and
    fallback is false'''
    print('########## Test to verify SSH login with radius authenication'
          ' enabled and fallback disabled to a secondary radius server'
          ' ##########\n')
    nofallbackenable(sw1)
    sleep(5)
    radiusauthenable(sw1)
    sleep(5)
    h1("service freeradius stop")
    h2("service freeradius start")
    ssh_newkey = 'Are you sure you want to continue connecting'
    switchipaddress = getswitchip(sw1)
    out = ""
    out += sw1("echo ", shell="bash")
    myssh = SSHCLIENT + " netop@" + switchipaddress
    p = pexpect.spawn(myssh)

    i = p.expect([ssh_newkey, 'password:', pexpect.EOF])

    if i == 0:
        p.sendline('yes')
        i = p.expect([ssh_newkey, 'password:', pexpect.EOF])
    if i == 1:
        p.sendline('testing')
        sleep(2)
    elif i == 2:
        assert i != 2, "Failed with SSH command"
    loginpass = p.expect(['password:', '#'])
    if loginpass == 0:
        p.sendline('dummypassword')
        p.expect('password:')
        p.sendline('dummypasswordagain')
        p.kill(0)
        assert loginpass != 0, "Failed to login via secondary radius" \
                               " server authentication"
    if loginpass == 1:
        p.sendline('end')
        p.kill(0)
        print(".### Passed secondary radius server authentication when"
              " primary radius server is not reachable ###\n")
        return True


def test_aaafeature(topology, step):
    sw1 = topology.get('sw1')
    h1 = topology.get('h1')
    h2 = topology.get('h2')

    assert sw1 is not None
    assert h1 is not None
    assert h2 is not None

    setupnet(h1, h2, sw1)

    loginsshlocal(sw1)

    loginsshradius(sw1)

    loginsshradiuswithlocalpassword(sw1)

    loginsshradiuswithfallback(h1, h2, sw1)

    loginsshlocalwrongpassword(sw1)

    loginsshlocalagain(sw1)

    loginsshradiuswithsecondaryserver(h1, h2, sw1)
