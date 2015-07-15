from smart import Error, _
from smart.util import pexpect

import os
import sys
import subprocess
from time import sleep
import pytest

from halonvsi.docker import *
from halonvsi.halon import *

def delay(sec=0.25):
    sleep(sec)

class myTopo(Topo):
    """Custom Topology Example
    H1[h1-eth0]<--->[1]S1[2]<--->H2[h2-eth0]
    """

    def build(self, hsts=2, sws=1, **_opts):
        self.hsts = hsts
        self.sws = sws

        "add list of hosts"
        for h in irange(1, hsts):
            host = self.addHost('h%s' % h)

        "add list of switches"
        for s in irange(1, sws):
            switch = self.addSwitch('s%s' % s)

        "Add links between nodes based on custom topo"
        self.addLink('h1', 's1')
        self.addLink('h2', 's1')

class aaaFeatureTest(HalonTest):

    def getHostOpts(self):
        ''' over riding the existing getHostOpts function present at halon.py
        to take our ubuntu image with freeradius installed '''
        opts = self.getNodeOpts()
        opts.update({'mounts':self.hostmounts})
        opts.update({'HostImage':'ubuntu_radius_rad:latest'})
        return opts

    def setupNet(self):
        # Create a topology with single Halon switch and
        # one host.

        topo = myTopo(hsts = 2, sws = 1, hopts = self.getHostOpts(),
                      sopts = self.getSwitchOpts(), switch = HalonSwitch,
                      host = HalonHost, link = HalonLink, controller = None,
                      build = True)

        self.net = Mininet(topo, switch = HalonSwitch, host = HalonHost,
                           link = HalonLink, controller = None, build = True)

    def getSwitchIP(self):
        ''' This function is to get switch IP addess
        '''
        s1 = self.net.switches [ 0 ]
        out = s1.cmd("ifconfig eth0")
        switchIpAddress = out.split("\n")[1].split()[1][5:]
        return switchIpAddress

    def getHostIP_1(self):
        ''' This function is to get host IP addess
        '''
        h1 = self.net.hosts [ 0 ]
        out = h1.cmd("ifconfig eth0")
        host_1_IpAddress = out.split("\n")[1].split()[1][5:]
        return host_1_IpAddress

    def getHostIP_2(self):
        ''' This function is to get host IP addess
        '''
        h2 = self.net.hosts [ 1 ]
        out = h2.cmd("ifconfig eth0")
        host_2_IpAddress = out.split("\n")[1].split()[1][5:]
        return host_2_IpAddress

    # Call checkAccessFiles to verify if configurations files are modified
    def checkAccessFiles(self):
        '''This function is to check if /etc/pam.d/common-*-access are modified
        based on the change in DB by cli
        '''
        s1 = self.net.switches [ 0 ]
        out = s1.cmd("cat /etc/pam.d/common-auth-access")
        lines = out.split('\n')
        for line in lines:
            if "auth" in line:
                print line
        print '\n'
        delay()
        out = s1.cmd("cat /etc/pam.d/common-account-access")
        lines = out.split('\n')
        for line in lines:
            if "account" in line:
                print line
        print '\n'
        delay()
        out = s1.cmd("cat /etc/pam.d/common-password-access")
        lines = out.split('\n')
        for line in lines:
            if "password" in line:
                print line
        print '\n'
        delay()
        out = s1.cmd("cat /etc/pam.d/common-session-access")
        lines = out.split('\n')
        for line in lines:
            if "session" in line:
                print line
        print '\n'

    def localAuthEnable(self):
        ''' This function is to enable local authentication in DB
        with CLI command'''
        s1 = self.net.switches [ 0 ]
        out = s1.cmdCLI("configure terminal")
        if 'Unknown command' in out:
            assert 0, "Failed to enter configuration terminal"

        out = s1.cmdCLI("aaa authentication login local")
        if 'Unknown command' in out:
            assert 0, "Failed to enable local authentication"

        s1.cmdCLI("exit")
        return True

    def radiusAuthEnable(self):
        ''' This function is to enable radius authentication in DB
        with CLI command'''
        s1 = self.net.switches [ 0 ]

        out = s1.cmdCLI("configure terminal")
        if 'Unknown command' in out:
            assert 0, "Failed to enter configuration terminal"

        out = s1.cmdCLI("aaa authentication login radius")
        if 'Unknown command' in out:
            assert 0, "Failed to enable radius authentication"

        s1.cmdCLI("exit")
        return True

    def noFallbackEnable(self):
        ''' This function is to disable fallback to local in DB
        with CLI command'''
        s1 = self.net.switches [ 0 ]

        out = s1.cmdCLI("configure terminal")
        if 'Unknown command' in out:
            assert 0, "Failed to enter configuration terminal"

        out = s1.cmdCLI("no aaa authentication login fallback error local")
        if 'Unknown command' in out:
            assert 0, "Failed to disable fallback to local authentication"

        s1.cmdCLI("exit")
        return True

    def FallbackEnable(self):
        ''' This function is to enable fallback to local in DB
        with CLI command'''
        s1 = self.net.switches [ 0 ]

        out = s1.cmdCLI("configure terminal")
        if 'Unknown command' in out:
            assert 0, "Failed to enter configuration terminal"

        out = s1.cmdCLI("aaa authentication login fallback error local")
        if 'Unknown command' in out:
            assert 0, "Failed to enable fallback to local authentication"

        s1.cmdCLI("exit")
        return True

    def setupRadiusserver(self):
        ''' This function is to setup radius server in the ubuntu image we are referring to
        '''
        print('\n=========================================================')
        print('*** Setup free radius freeradius ***')
        print('===========================================================')
        h1 = self.net.hosts [ 0 ]
        hostIp_1_Address = self.getHostIP_1()
        out = h1.cmd("sed -i '76s/steve/admin/' /etc/freeradius/users")
        out = h1.cmd("sed -i '76s/#admin/admin/' /etc/freeradius/users")
        out = h1.cmd("sed -i '196s/192.168.0.0/"+hostIp_1_Address+"/' /etc/freeradius/clients.conf")
        out = h1.cmd("sed -i '196,199s/#//' /etc/freeradius/clients.conf")

        h1.cmd("service freeradius stop")
        sleep(1)
        out = h1.cmd("service freeradius start")

        h2 = self.net.hosts [ 1 ]
        hostIp_2_Address = self.getHostIP_2()
        out = h2.cmd("sed -i '76s/steve/admin/' /etc/freeradius/users")
        out = h2.cmd("sed -i '76s/#admin/admin/' /etc/freeradius/users")
        out = h2.cmd("sed -i '196s/192.168.0.0/"+hostIp_2_Address+"/' /etc/freeradius/clients.conf")
        out = h2.cmd("sed -i '196,199s/#//' /etc/freeradius/clients.conf")

        h2.cmd("service freeradius stop")
        sleep(1)
        out = h2.cmd("service freeradius start")

    def setupRadiusclient(self):
        ''' This function is to setup radius client in the switch
        '''
        print('\n=========================================================')
        print('*** Setup radius client in the switch ***')
        print('===========================================================')
        s1 = self.net.switches [ 0 ]
        host_1_IpAddress = self.getHostIP_1()
        host_2_IpAddress = self.getHostIP_2()
        s1.cmd("mkdir /etc/raddb/")
        s1.cmd("touch /etc/raddb/server")
        sleep(1)
        out = s1.cmdCLI("configure terminal")
        if 'Unknown command' in out:
            assert 0, "Failed to enter configuration terminal"

        sleep(1)
        s1.cmdCLI("radius-server host " + host_1_IpAddress)
        sleep(1)
        s1.cmdCLI("radius-server host " + host_2_IpAddress)
        sleep(2)
        s1.cmdCLI("radius-server timeout 1")
        sleep(2)
        s1.cmdCLI("radius-server retries 0")
        s1.cmdCLI("exit")

    def loginSSHlocal(self):
        '''This function is to verify local authentication is successful when
        radius is false and fallback is true'''
        print('\n=========================================================')
        print('*** Test to verify SSH login with local authenication enabled ***')
        print('===========================================================')
        s1 = self.net.switches [ 0 ]
        self.checkAccessFiles()
        ssh_newkey = 'Are you sure you want to continue connecting'
        switchIpAddress = self.getSwitchIP()
        myssh = "ssh admin@" + switchIpAddress
        p = pexpect.spawn(myssh)

        i = p.expect([ssh_newkey, 'password:', pexpect.EOF])

        if i == 0:
            p.sendline('yes')
            i = p.expect([ssh_newkey, 'password:', pexpect.EOF])
        if i == 1:
            p.sendline('admin')
        elif i == 2:
            assert 0, "Failed with ssh command"
        p.expect('#')
        p.sendline('exit')
        p.kill(0)
        return True

    def loginSSHradius(self):
        '''This function is to verify radius authentication is successful when
        radius is true and fallback is false'''
        print('\n=========================================================')
        print('*** Test to verify SSH login with radius authenication enabled and fallback disabled ***')
        print('===========================================================')
        s1 = self.net.switches [ 0 ]
        retFallback = self.noFallbackEnable()
        sleep(5)
        retAuth = self.radiusAuthEnable()
        sleep(5)
        self.checkAccessFiles()
        ssh_newkey = 'Are you sure you want to continue connecting'
        switchIpAddress = self.getSwitchIP()
        myssh = "ssh admin@" + switchIpAddress
        p = pexpect.spawn(myssh)

        i = p.expect([ssh_newkey, 'password:', pexpect.EOF])

        if i == 0:
            p.sendline('yes')
            i = p.expect([ssh_newkey, 'password:', pexpect.EOF])
        if i == 1:
            p.sendline('testing')
        elif i == 2:
            assert 0, "Failed with ssh command"
        loginpass = p.expect(['password:', '#'])
        if loginpass == 0:
            p.sendline('dummypassword')
            p.expect('password:')
            p.sendline('dummypasswordagain')
            p.kill(0)
            assert 0, "Failed to login via radius authentication"
        if loginpass == 1:
            p.sendline('exit')
            p.kill(0)
            return True

    def loginSSHradiusWithLocalPassword(self):
        ''' This is a negative test case to verify login with radius authentication by giving local
        password'''
        print('\n=========================================================')
        print('*** Test to verify SSH login with radius authenication enabled and fallback disabled and using local password ***')
        print('===========================================================')
        s1 = self.net.switches [ 0 ]
        self.checkAccessFiles()
        ssh_newkey = 'Are you sure you want to continue connecting'
        switchIpAddress = self.getSwitchIP()
        myssh = "ssh admin@" + switchIpAddress
        p = pexpect.spawn(myssh)

        i = p.expect([ssh_newkey, 'password:', pexpect.EOF])

        if i == 0:
            p.sendline('yes')
            i = p.expect([ssh_newkey, 'password:', pexpect.EOF])
        if i == 1:
            p.sendline('admin')
        elif i == 2:
            assert 0, "Failed with ssh command"
        loginpass = p.expect(['password:', '#'])
        if loginpass == 0:
            p.sendline('admin')
            p.expect('password:')
            p.sendline('admin')
            p.expect('Permission denied')
            p.kill(0)
            return True
        if loginpass == 1:
            p.sendline('exit')
            p.kill(0)
            assert 0, "Failed to validate radius authetication with local password"

    def loginSSHradiusWithFallback(self):
        ''' This function is to verify radius authentication when fallback is enabled. Login with local
        password should work when raddius server is un reachable'''
        print('\n=========================================================')
        print('*** Test to verify SSH login with radius authenication enabled and fallback Enabled ***')
        print('===========================================================')
        s1 = self.net.switches [ 0 ]
        h1 = self.net.hosts [ 0 ]
        h2 = self.net.hosts [ 1 ]
        retFallback = self.FallbackEnable()
        self.checkAccessFiles()
        host_2_IpAddress = self.getHostIP_2()
        s1.cmdCLI("configure terminal")
        s1.cmdCLI("no radius-server host " + host_2_IpAddress)
        h1.cmd("service freeradius stop")
        h2.cmd("service freeradius stop")

        ssh_newkey = 'Are you sure you want to continue connecting'
        switchIpAddress = self.getSwitchIP()
        myssh = "ssh admin@" + switchIpAddress
        p = pexpect.spawn(myssh)

        i = p.expect([ssh_newkey, 'password:', pexpect.EOF])

        if i == 0:
            p.sendline('yes')
            i = p.expect([ssh_newkey, 'password:', pexpect.EOF])
        if i == 1:
            p.sendline('Testing')
        elif i == 2:
            assert 0, "Failed with ssh command"
        loginpass = p.expect(['password:', '#'])
        if loginpass == 0:
            p.sendline('admin')
            p.expect('#')
            p.sendline('exit')
            p.kill(0)
            s1.cmdCLI("radius-server host " + host_2_IpAddress)
            s1.cmdCLI("exit")
            return True
        if loginpass == 1:
            p.sendline('exit')
            p.kill(0)
            s1.cmdCLI("radius-server host " + host_2_IpAddress)
            s1.cmdCLI("exit")
            assert 0, "Failed to validate radius authetication when server is not reachable"

    def loginSSHlocalWrongPassword(self):
        ''' This is a negative test case, we enable only local authetication and try logging with
        wrong password'''
        print('\n=========================================================')
        print('*** Test to verify SSH login with local authenication enabled and Wrong password ***')
        print('===========================================================')
        s1 = self.net.switches [ 0 ]
        retFallback = self.noFallbackEnable()
        sleep(5)
        retLocalAuth = self.localAuthEnable()
        sleep(5)
        self.checkAccessFiles()
        ssh_newkey = 'Are you sure you want to continue connecting'
        switchIpAddress = self.getSwitchIP()
        myssh = "ssh admin@" + switchIpAddress
        p = pexpect.spawn(myssh)

        i = p.expect([ssh_newkey, 'password:', pexpect.EOF])

        if i == 0:
            p.sendline('yes')
            i = p.expect([ssh_newkey, 'password:', pexpect.EOF])
        if i == 1:
            p.sendline('admin1')
        elif i == 2:
            assert 0, "Failed with SSH command"
        loginpass=p.expect(['password:', '#'])
        if loginpass == 0:
            p.sendline('admin2')
            p.expect('password:')
            p.sendline('admin3')
            p.expect('Permission denied')
            p.kill(0)
            return True
        if loginpass == 1:
            p.sendline('exit')
            p.kill(0)
            assert 0, "Failed to validate local authentication"

    def loginSSHlocalAgain(self):
        ''' This is again a test case to verify, when local authetication is enabled login should properly
        work with local password'''
        print('\n=========================================================')
        print('*** Test to verify SSH login with local authenication enabled again with correct password ***')
        print('===========================================================')
        s1 = self.net.switches [ 0 ]
        self.checkAccessFiles()
        ssh_newkey = 'Are you sure you want to continue connecting'
        switchIpAddress = self.getSwitchIP()
        myssh = "ssh admin@" + switchIpAddress
        p = pexpect.spawn(myssh)

        i = p.expect([ssh_newkey, 'password:', pexpect.EOF])

        if i == 0:
            p.sendline('yes')
            i = p.expect([ssh_newkey, 'password:', pexpect.EOF])
        if i == 1:
            p.sendline('admin')
        elif i == 2:
            assert 0, "Failed with SSH command"
        loginpass = p.expect(['password:', '#'])
        if loginpass == 0:
            p.sendline('admin2')
            p.expect('password:')
            p.sendline('admin3')
            p.expect('Permission denied')
            p.kill(0)
            assert 0, "Failed to validate local authentication with correct password"
        if loginpass == 1:
            p.sendline('exit')
            p.kill(0)
            return True


    def loginSSHradiusWithSecondaryServer(self):
        '''This function is to verify radius authentication with the secondary radius server
         when unable to reach primary server - radius is true and fallback is false'''
        print('\n=========================================================')
        print('*** Test to verify SSH login with radius authenication enabled and fallback disabled to a secondary radius server***')
        print('===========================================================')
        s1 = self.net.switches [ 0 ]
        retFallback = self.noFallbackEnable()
        sleep(5)
        retAuth = self.radiusAuthEnable()
        sleep(5)
        self.checkAccessFiles()
        h1 = self.net.hosts [ 0 ]
        h2 = self.net.hosts [ 1 ]
        h1.cmd("service freeradius stop")
        h2.cmd("service freeradius start")
        ssh_newkey = 'Are you sure you want to continue connecting'
        switchIpAddress = self.getSwitchIP()
        myssh = "ssh admin@" + switchIpAddress
        p = pexpect.spawn(myssh)

        i = p.expect([ssh_newkey, 'password:', pexpect.EOF])

        if i == 0:
            p.sendline('yes')
            i = p.expect([ssh_newkey, 'password:', pexpect.EOF])
        if i == 1:
            p.sendline('testing')
            sleep(2)
        elif i == 2:
            assert 0, "Failed with ssh command"
        loginpass = p.expect(['password:', '#'])
        if loginpass == 0:
            p.sendline('dummypassword')
            p.expect('password:')
            p.sendline('dummypasswordagain')
            p.kill(0)
            assert 0, "Failed to login via secondary radius server authentication"
        if loginpass == 1:
            p.sendline('exit')
            p.kill(0)
            return True

class Test_aaafeature:
    def setup(self):
        pass

    def teardown(self):
        pass

    def setup_class(cls):
        Test_aaafeature.test = aaaFeatureTest()
        pass

    def teardown_class(cls):
    # Stop the Docker containers, and
    # mininet topology
       Test_aaafeature.test.net.stop()

    def setup_method(self, method):
        pass

    def teardown_method(self, method):
        pass

    def __del__(self):
        del self.test

    def test_setupRadiusserver(self):
        if self.test.setupRadiusserver():
            print 'Passed setupRadiusserver'

    def test_setupRadiusclient(self):
        if self.test.setupRadiusclient():
            print 'setupRadiusclient'

    def test_loginSSHlocal(self):
        if self.test.loginSSHlocal():
            print 'Passed loginSSHlocal'

    def test_loginSSHradius(self):
        if self.test.loginSSHradius():
            print 'Passed loginSSHradius'

    def test_loginSSHradiusWithLocalPassword(self):
        if self.test.loginSSHradiusWithLocalPassword():
            print 'Passed negative test case loginSSHradiusWithLocalPassword'

    def test_loginSSHradiusWithFallback(self):
        if self.test.loginSSHradiusWithFallback():
            print 'Passed loginSSHradiusWithFallback'

    def test_loginSSHlocalWrongPassword(self):
        if self.test.loginSSHlocalWrongPassword():
            print 'Passed negative test case loginSSHlocalWrongPassword'

    def test_loginSSHlocalAgain(self):
        if self.test.loginSSHlocalAgain():
            print 'Passed loginSSHlocalAgain'

    def test_loginSSHradiusWithSecondaryServer(self):
        if self.test.loginSSHradiusWithSecondaryServer():
            print 'Passed loginSSHradiusWithSecondaryServer'
