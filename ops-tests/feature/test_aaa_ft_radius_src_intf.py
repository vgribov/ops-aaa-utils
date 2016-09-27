# Copyright (C) 2016 Hewlett Packard Enterprise Development LP
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

# The purpose of this test is to test DHCP server address lease
# configurations for dynamic allocations and verify the
# allocations in OVSDB and DHCP client interface.

# For this test, we need 2 hosts connected to a switch
# which start exchanging DHCP messages.
#
# S1 [interface 1]<--->[interface 1] H1
# S1 [interface 2]<--->[interface 2] H2

from pytest import mark
from pdb import set_trace
from time import sleep
import pexpect

TOPOLOGY = """
#
# +-------+                  +-------+
# |       |     +---v---+    |       |
# |  h1   <----->  sw1  <---->  h2   |
# |       |     +-------+    |       |
# +-------+                  +-------+
#

# Nodes
[type=openswitch name="Switch 1"] sw1
[type=host image="host/freeradius-ubuntu:latest" name="host 1"] h1
[type=oobmhost image="host/freeradius-ubuntu:latest" name="Host 2"] h2


# Links
sw1:if01 -- h1:if01
sw1:eth0 -- h2:eth0
"""

host1_pool = "host1"
host2_pool = "host2"
start_ipv4_address_pool1 = "10.0.0.1"
end_ipv4_address_pool1 = "10.0.0.100"
start_ipv4_address_pool2 = "20.0.0.1"
end_ipv4_address_pool2 = "20.0.0.100"

ssh_client = "/usr/bin/ssh -q -o UserKnownHostsFile=/dev/null" \
    "  -o StrictHostKeyChecking=no"

switches = []
hosts = []
USER_1 = "user1"
USER_NEW = "user1"


def configure(sw1):
    print('\n### Test DHCP server dynamic IPV4 configuration ###\n')
    print('\n### Configuring dynamic IPV4 address allocation ###\n')

    sw1p1 = sw1.ports['if01']

    # Configure switch s1
    # Configure interface 1 on switch s1
    with sw1.libs.vtysh.ConfigInterface(sw1p1) as ctx:
        ctx.no_shutdown()
        ctx.ip_address("10.0.10.1/8")
        ctx.ipv6_address("2000::1/120")


    sw1("configure terminal")
    sw1("int loopback 1")
    sw1("ip address 13.0.13.2/8")
    sw1("end")

    # FIXME
    sw1("configure terminal")
    sw1("dhcp-server")
    sw1("range host1 start-ip-address %s end-ip-address %s"
        % (start_ipv4_address_pool1, end_ipv4_address_pool1))

    sw1("range host2 start-ip-address %s end-ip-address %s"
        % (start_ipv4_address_pool2, end_ipv4_address_pool2))

    sw1("end")
    """with sw1.libs.vtysh.ConfigDhcpServer() as ctx:
        ctx.range_start_ip_address_end_ip_address("host1",
                                                  start_ipv4_address_pool1,
                                                  end_ipv4_address_pool1)
        ctx.range_start_ip_address_end_ip_address("host2",
                                                  start_ipv4_address_pool2,
                                                  end_ipv4_address_pool2)"""


def dhcp_server_dynamic_ipv4_pool_config(sw1):
    print('\n### Verify DHCP server dynamic IPV4 pool config in db ###\n')

    # Parse "show dhcp-server" output.
    # This section will have all the DHCP server
    # dynamic IPV4 pool configuration entries.
    # Then parse line by line to match the contents
    dump = sw1.libs.vtysh.show_dhcp_server()
    sorted(dump.values())
    assert (host1_pool == dump['pools'][1]['pool_name'] or
            host1_pool == dump['pools'][0]['pool_name']) and \
        (start_ipv4_address_pool1 == dump['pools'][1]['start_ip'] or
         start_ipv4_address_pool1 == dump['pools'][0]['start_ip']) and \
        (end_ipv4_address_pool1 == dump['pools'][1]['end_ip'] or
         end_ipv4_address_pool1 == dump['pools'][0]['end_ip'])
    assert (host2_pool == dump['pools'][0]['pool_name'] or
            host2_pool == dump['pools'][1]['pool_name']) and \
        (start_ipv4_address_pool2 == dump['pools'][0]['start_ip'] or
         start_ipv4_address_pool2 == dump['pools'][1]['start_ip']) and \
        (end_ipv4_address_pool2 == dump['pools'][0]['end_ip'] or
         end_ipv4_address_pool2 == dump['pools'][1]['end_ip'])


def configure_dhcp_client(h1, h2):
    print('\n### Configure DHCP clients for '
          'dynamic IPV4 address in db ###\n')
    h1p1 = h1.ports['if01']
    h2p1 = h2.ports['eth0']

    h1("sed -i 's/#timeout 60/timeout 30/g' /etc/dhcp/dhclient.conf")

    # FIXME
    h1("ifconfig -a")
    h1("ip addr del 10.0.0.1/8 dev {h1p1}".format(**locals()))
    h1("dhclient {h1p1}".format(**locals()))
    h1("sed -i 's/timeout 30/#timeout 60/g' /etc/dhcp/dhclient.conf")

    #set_trace()
    #h2("sed -i 's/#timeout 60/timeout 30/g' /etc/dhcp/dhclient.conf")
    #h2("ifconfig -a")
    #h2("ip addr del 10.0.0.2/8 dev {h2p1}".format(**locals()))
    #h2("dhclient {h2p1}".format(**locals()))
    #h2("sed -i 's/timeout 30/#timeout 60/g' /etc/dhcp/dhclient.conf")


def dhcp_client_dynamic_ipv4_address_config(h1, h2, sw1):
    print('\n### Verify DHCP clients h1 and h2 '
          'dynamic IPV4 address config in db ###\n')
    h1p1 = h1.ports['if01']
    h2p1 = h2.ports['if01']

    ifconfighost1macaddr = ""
    ifconfighost2macaddr = ""
    ifconfighost1ipv4addr = ""
    ifconfighost2ipv4addr = ""
    ifconfigipv4prefixpattern = "inet addr:"
    ifconfigipv4addridx = 1
    ifconfigmacaddridx = 4
    ifconfigipv4addrlinenum = 1
    ifconfigmacaddrlinenum = 0
    dhcpmacaddrhost1 = ""
    dhcpmacaddrhost2 = ""
    dhcpmacaddridx = 5
    dhcpipv4addrhost1 = ""
    dhcpipv4addrhost2 = ""
    dhcpipv4addridx = 6

    # Parse the "ifconfig" outputs for interfaces
    # h1-eth0 and h2-eth0 for hosts 1 and 2
    # respectively and save the values for ipaddresses and mac
    # addresses into variables above
    dump = h1("ifconfig {h1p1}".format(**locals()))
    host_1_ip_address = dump.split("\n")[1].split()[1][5:]
    lines = dump.split('\n')
    count = 0
    for line in lines:
        if count == ifconfigmacaddrlinenum:
            outstr = line.split()
            ifconfighost1macaddr = outstr[ifconfigmacaddridx]
        elif count == ifconfigipv4addrlinenum:
            outstr = line.split()
            ifconfighost1ipv4addrtemp1 = outstr[ifconfigipv4addridx]
            ifconfighost1ipv4addrtemp2 = ifconfighost1ipv4addrtemp1.split(':')
            ifconfighost1ipv4addr = ifconfighost1ipv4addrtemp2[1]
        count = count + 1

    dump = h2("ifconfig {h2p1}".format(**locals()))
    host_2_ip_address = dump.split("\n")[1].split()[1][5:]
    lines = dump.split('\n')
    count = 0
    for line in lines:
        if count == ifconfigmacaddrlinenum:
            outstr = line.split()
            ifconfighost2macaddr = outstr[ifconfigmacaddridx]
        elif count == ifconfigipv4addrlinenum:
            outstr = line.split()
            ifconfighost2ipv4addrtemp1 = outstr[ifconfigipv4addridx]
            ifconfighost2ipv4addrtemp2 = ifconfighost2ipv4addrtemp1.split(':')
            ifconfighost2ipv4addr = ifconfighost2ipv4addrtemp2[1]
        count = count + 1

    # Parse the "show dhcp-server leases" output
    # and verify if the values for interfaces
    # h1-eth0 and h2-eth0 for hosts
    # 1 and 2 respectively are present in the lease dB
    valid_config = 0
    dump = sw1.libs.vtysh.show_dhcp_server_leases()
    if ifconfighost1macaddr == dump[host_1_ip_address]['mac_address']:
        dhcpipv4addrhost1 = dump[host_1_ip_address]['ip_address']
        valid_config += 1
        assert dhcpipv4addrhost1 == ifconfighost1ipv4addr
    if ifconfighost2macaddr == dump[host_2_ip_address]['mac_address']:
        dhcpipv4addrhost2 = dump[host_2_ip_address]['ip_address']
        valid_config += 1
        assert dhcpipv4addrhost2 == ifconfighost2ipv4addr
    assert valid_config == 2 , "Invalid entry in DHCP Leases Database"


def setupradiusserver(step):
    """ This function is to setup radius server in the ops-host image
    """
    h1 = hosts[0]
    h2 = hosts[1]

    switchip = get_switch_ip(step)
    print("SwitchIP:" + switchip)
    out = h2("sed -i \"76s/steve/steve/\" /etc/freeradius/users")
    out = h2("sed -i \"76s/#steve/steve/\" /etc/freeradius/users")
    out = h2("sed -i \"77s/Framed-User/Administrative-User/\" /etc/freeradius/users")
    out = h2("sed -i \"77s/#//\" /etc/freeradius/users")
    out = h2("sed -i \"196s/192.168.0.0/"+switchip+"/\" "
             "/etc/freeradius/clients.conf")
    out = h2("sed -i \"196,199s/#//\" /etc/freeradius/clients.conf")

    h2("service freeradius stop")
    sleep(2)
    out = h2("service freeradius start")
    assert ("fail") not in out, "Failed to start freeradius on host"



    print("SwitchIP:" + switchip)
    out = h1("sed -i \"76s/steve/steve/\" /etc/freeradius/users")
    out = h1("sed -i \"76s/#steve/steve/\" /etc/freeradius/users")
    out = h1("sed -i \"77s/Framed-User/Administrative-User/\" /etc/freeradius/users")
    out = h1("sed -i \"77s/#//\" /etc/freeradius/users")
    out = h1("sed -i \"196s/192.168.0.0/0.0.0.0/\" "
             "/etc/freeradius/clients.conf")
    out = h1("sed -i \"196s/24/0/\" "
             "/etc/freeradius/clients.conf")
    out = h1("sed -i \"196,199s/#//\" /etc/freeradius/clients.conf")

    h1("service freeradius stop")
    sleep(2)
    out = h1("service freeradius start")
    assert ("fail") not in out, "Failed to start freeradius on host"

    step("Configured radius server on host\n")

def setup_tacacs_server(step, new_user, new_pass):
    """ This function is to setup tacacs server
    """
    h1 = hosts[0]
    h2 = hosts[1]
    #host_ip = get_host_ip(step, 1)
    step("####### Configure TACACS+ servers start #######")
    step("#### Stop tac_plus daemon for servers ####")
    h1("service tac_plus stop")
    h2("service tac_plus stop")

    sleep(2)
    #step("#### Add user " + new_user + " to host " + host_ip + "  ####")
    #content = "\nuser = " + new_user + " {\n        pap = cleartext " + new_pass + "\n        service = exec {\n         priv-lvl = 15\n        }\n}"

    #out = h2("echo $\'" + content + "\' >> /etc/tacacs/tac_plus.conf")
    #out = h2("cat /etc/tacacs/tac_plus.conf")
    #print(out)
    #assert (content) in out, "Failed to add user"
    step("#### Restart tac_plus daemon for servers ####")
    out = h1("service tac_plus start")
    assert ("fail") not in out, "Failed to start tac_plus on host 1"
    out = h2("service tac_plus start")
    assert ("fail") not in out, "Failed to start tac_plus on host 2"

    step("####### Configure TACACS+ servers succeed #######")


def setup_source_intf_address_int_1(step):
    """ This function is to setup TACACS+ source interface
    """
    step("####### Configure src intf address of interface 1 start #######")
    s1 = switches[0]
    out = s1("configure terminal")
    assert "Unknown command" not in out, \
        "Failed to enter configuration terminal"

    sleep(2)
    s1("ip source-interface all " + "10.0.10.1")
    s1("exit")
    s1("end")
    step("####### Configure src intf address of interface 1 succeed #######")


def setup_source_intf_interface_int_1(step):
    """ This function is to setup TACACS+ source interface
    """
    step("####### Configure src intf name of interface 1 start #######")
    s1 = switches[0]
    out = s1("configure terminal")
    assert "Unknown command" not in out, \
        "Failed to enter configuration terminal"

    sleep(2)
    s1("ip source-interface all interface " + "1")
    s1("exit")
    s1("end")
    step("####### Configure src intf name of interface 1 succeed #######")


def setup_source_intf_address_loopback(step):
    """ This function is to setup TACACS+ source interface
    """
    step("####### Configure src intf address of loopback 1 start #######")
    s1 = switches[0]
    out = s1("configure terminal")
    assert "Unknown command" not in out, \
        "Failed to enter configuration terminal"

    sleep(2)
    s1("ip source-interface all " + "13.0.13.2")
    s1("exit")
    s1("end")
    step("####### Configure src intf address of loopback 1  succeed #######")

def setup_source_intf_interface_loopback(step):
    """ This function is to setup TACACS+ source interface
    """
    step("####### Configure src intf name of loopback 1  start #######")
    s1 = switches[0]
    out = s1("configure terminal")
    assert "Unknown command" not in out, \
        "Failed to enter configuration terminal"

    sleep(2)
    s1("ip source-interface all interface " + "loopback 1")
    s1("exit")
    s1("end")
    step("####### Configure src intf name of loopback 1  succeed #######")


def setup_source_intf_address_mgmt(step):
    """ This function is to setup TACACS+ source interface
    """
    step("####### Configure src intf address of mgmt interface start #######")
    s1 = switches[0]
    out = s1("configure terminal")
    assert "Unknown command" not in out, \
        "Failed to enter configuration terminal"

    sleep(2)
    switch_ip = get_switch_ip(step)
    s1("ip source-interface all  " + switch_ip)
    s1("exit")
    s1("end")
    step("####### Configure src intf address of mgmt interface  succeed #######")

def setup_source_intf_remove(step):
    """ This function is to setup TACACS+ source interface
    """
    step("####### Remove src intf configuration start #######")
    s1 = switches[0]
    out = s1("configure terminal")
    assert "Unknown command" not in out, \
        "Failed to enter configuration terminal"

    sleep(2)
    switch_ip = get_switch_ip(step)
    s1("no ip source-interface all ")
    s1("exit")
    s1("end")
    step("####### Remove src intf configuration succeed #######")

def setup_tacacs_client(step):
    """ This function is to setup TACACS+ client in the switch
    """
    step("####### Configure TACACS+ client (on OpenSwitch) start #######")
    s1 = switches[0]
    host_1_ip_address = get_host_ip(step, 0)
    host_2_ip_address = get_host_ip_2(step, 1)
    print("TACACS+ Server:" + host_1_ip_address)
    print("TACACS+ Server:" + host_2_ip_address)
    sleep(2)
    out = s1("configure terminal")
    assert "Unknown command" not in out, \
        "Failed to enter configuration terminal"

    sleep(2)
    s1("tacacs-server host " + host_1_ip_address + " key tac_test timeout 15")
    s1("tacacs-server host " + host_2_ip_address + " key tac_test timeout 15")
    s1("ip source-interface all  " + "10.0.10.1")
    s1("aaa group server tacacs+ sg1")
    s1("server " + host_1_ip_address)
    #s1("server " + host_2_ip_address)
    s1("end")
    step("####### Configure TACACS+ client (on OpenSwitch) succeed #######")



def enable_tacacs_authentication_by_group(step):
    """ This function is to enable TACACS+ authentication in DB
    with CLI command"""
    step("####### Configure TACACS+ authentication  #######")
    s1 = switches[0]
    out = s1("echo ", shell="bash")
    out = s1("configure terminal")
    assert "Unknown command" not in out, \
        "Failed to enter configuration terminal"

    s1("aaa authentication login default group sg1")
    s1("exit")

    out = s1("show running-config")
    assert "aaa authentication login default group sg1" in out, \
        "Failed to configure aaa authentication by server group sg1"


def get_switch_ip(step):
    """ This function is to get switch IP addess
    """
    s1 = switches[0]
    out = s1("ifconfig eth0", shell="bash")
    switch_ip = out.split("\n")[1].split()[1][5:]
    return switch_ip


def get_host_ip(step, host_id):
    """ This function is to get host IP addess
    """
    host = hosts[host_id]
    out = host("ifconfig %s" % host.ports["if01"])
    host_ip_address = out.split("\n")[1].split()[1][5:]
    return host_ip_address

def get_host_ip_2(step, host_id):
    """ This function is to get host IP addess
    """
    host = hosts[host_id]
    out = host("ifconfig %s" % host.ports["eth0"])
    host_ip_address = out.split("\n")[1].split()[1][5:]
    return host_ip_address


def login_ssh_tacacs(step, username, password):
    """This function is to verify TACACS+ authentication is successful
    """
    step("####### Test SSH login with TACACS+ authentication start #######")
    s1 = switches[0]
    ssh_newkey = "Are you sure you want to continue connecting"
    switch_ip = get_switch_ip(step)
    step("#### Switch ip address: " + switch_ip + " ####")
    step("#### Running configuration ####")
    run = s1("show running-config")
    print(run)
    out = s1("echo ", shell="bash")
    myssh = ssh_client + " " + username + "@" + switch_ip
    p = pexpect.spawn(myssh)

    address_known = p.expect([ssh_newkey, "password:", pexpect.EOF])
    if address_known == 0:
        p.sendline("yes")
        address_known = p.expect([ssh_newkey, "password:", pexpect.EOF])
    if address_known == 1:
        p.sendline(password)
    assert address_known != 2, "Failed with SSH command"
    login_pass = p.expect(["password:", "#"])
    if login_pass == 0:
        p.sendline("dummypassword")
        p.expect("password:")
        p.sendline("dummypasswordagain")
        p.kill(0)
        #set_trace()
        assert login_pass != 0, "Failed to login via TACACS+ authentication"
    if login_pass == 1:
        p.sendline("exit")
        p.kill(0)
    step("####### Test SSH login with TACACS+ authentication succeed #######")


@mark.platform_incompatible(['ostl'])
def test_aaa_ft_authentication(topology, step):
    global switches, hosts
    ops1 = topology.get('sw1')
    hs1 = topology.get('h1')
    hs2 = topology.get('h2')

    assert ops1 is not None
    assert hs1 is not None
    assert hs2 is not None

    switches = [ops1]
    hosts = [hs1, hs2]

    ops1.name = "ops1"
    hs1.name = "hs1"
    hs2.name = "hs2"


    # copied from src intf topo (start)

    step('\n########## Test DHCP server dynamic '
         'IPV4 configuration ##########\n')
    configure(ops1)
    configure_dhcp_client(hs1, hs2)

    setupradiusserver(step)
    set_trace()

    enable_tacacs_authentication_by_group(step)

    setup_source_intf_address_int_1(step)
    set_trace()
    login_ssh_tacacs(step, USER_1, USER_1)

    setup_source_intf_interface_int_1(step)
    login_ssh_tacacs(step, USER_1, USER_1)

    setup_source_intf_address_loopback(step)
    login_ssh_tacacs(step, USER_1, USER_1)

    setup_source_intf_interface_loopback(step)
    login_ssh_tacacs(step, USER_1, USER_1)

    setup_source_intf_address_mgmt(step)
    login_ssh_tacacs(step, USER_1, USER_1)

    setup_source_intf_remove(step)
    login_ssh_tacacs(step, USER_1, USER_1)
