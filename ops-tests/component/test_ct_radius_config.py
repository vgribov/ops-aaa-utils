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


TOPOLOGY = """
#
# +--------+
# |  ops1  |
# +--------+
#

# Nodes
[type=openswitch name="Switch 1"] ops1
"""
from pdb import set_trace

DEFAULT_RADIUS_TIMEOUT = "5"
DEFAULT_RADIUS_AUTH_PORT = "1812"
DEFAULT_RADIUS_PASSKEY = "testing123-1"
DEFAULT_RADIUS_AUTH_TYPE = "pap"
DEFAULT_RADIUS_RETRIES = "1"
DEFAULT_RADIUS_GROUP = "radius"
COUNT_RADIUS_SERVER = 0
COUNT_SG1_SERVER = 0
COUNT_SG2_SERVER = 0
CHECK_SUCCESS = 1
CHECK_FAILED = -1


def increment_radius_server():
    global COUNT_RADIUS_SERVER
    COUNT_RADIUS_SERVER = COUNT_RADIUS_SERVER + 1

def increment_sg1_server():
    global COUNT_SG1_SERVER
    COUNT_SG1_SERVER = COUNT_SG1_SERVER + 1

def clear_sg1_server():
    global COUNT_SG1_SERVER
    COUNT_SG1_SERVER = 0

def get_radius_server_details(lines, server_name):
    lines = [line.strip().replace(' ', '') for line in lines]

    ''' collect all the RADIUS server details '''
    server_line_index = lines.index("Server-Name:" + server_name)
    server_info = lines[server_line_index : server_line_index + 8]

    ''' collect RADIUS server parameters
        in format (name, port, key, timeout, retries, auth-type, server-group, default-priority)
    '''
    params = [param.split(":")[-1] for param in server_info]
    if params[0] in server_name:
        params[0] = server_name
    print (params)
    return tuple(params)

def get_radius_server_group_rows(lines, sg_name):
    groups = []
    lines = [line.strip().replace(' ', '') for line in lines]

    ''' collect all the RADIUS server details for specified server group_name '''
    for line in lines:
        if sg_name in line:
            params = line.split("|")
            groups.append(tuple(params))
    print(groups)
    return groups

def radius_add_server_no_options(dut, step):
    step('\n### === server (with no options) addition test start === ###')
    dut("configure terminal")
    dut("radius-server host 1.1.1.1")
    dut("end")
    increment_radius_server()
    dump = dut("show radius-server detail")
    lines = dump.splitlines()
    count = 0

    server_params = ("1.1.1.1", DEFAULT_RADIUS_AUTH_PORT,
                      DEFAULT_RADIUS_PASSKEY, DEFAULT_RADIUS_TIMEOUT, DEFAULT_RADIUS_RETRIES,
                      DEFAULT_RADIUS_AUTH_TYPE, DEFAULT_RADIUS_GROUP, str(COUNT_RADIUS_SERVER))
    print(server_params)

    if server_params == get_radius_server_details(lines, "1.1.1.1"):
        step('\n### server (with no options) present in command - '
                 'passed ###')
        count = count + 1

    ''' now check the running config '''
    dump = dut("show running-config")
    lines = dump.splitlines()
    for line in lines:
        if "radius-server host 1.1.1.1" in line:
            step('\n### server (with no options) present in running config - '
                 'passed ###')
            count = count + 1
            print(count)
    assert count == 2,\
            '\n### server (with no options) addition test failed ###'

    step('\n### server (with no options) addition test passed ###')
    step('\n### === server (with no options) addition test end === ###\n')


def radius_add_server_with_valid_passkey(dut, step):
    step('\n### === server (with valid passkey) addition test start === ###')
    dut("configure terminal")
    dut("radius-server host 1.1.1.2 key test-key")
    dut("end")
    increment_radius_server()
    dump = dut("show radius-server detail")
    lines = dump.splitlines()
    count = 0

    server_params = ("1.1.1.2", DEFAULT_RADIUS_AUTH_PORT,
                     "test-key", DEFAULT_RADIUS_TIMEOUT, DEFAULT_RADIUS_RETRIES,
                     DEFAULT_RADIUS_AUTH_TYPE, DEFAULT_RADIUS_GROUP, str(COUNT_RADIUS_SERVER))
    if server_params == get_radius_server_details(lines, "1.1.1.2"):
        step('\n### server (with valid passkey) present as per show cli - '
                 'passed ###')
        count = count + 1

    ''' now check the running config '''
    dump = dut("show running-config")
    lines = dump.splitlines()
    for line in lines:
        if ("radius-server host 1.1.1.2 key test-key" in line):
            step('\n### server (with valid passkey) present in running config - '
                 'passed ###')
            count = count + 1

    assert count == 2,\
            '\n### server (with valid passkey) addition test failed ###'

    step('\n### server (with valid passkey) addition test passed ###')
    step('\n### === server (with valid passkey) addition test end === ###\n')


def radius_add_server_with_valid_timeout(dut, step):
    step('\n### === server (with valid timeout) addition test start === ###')
    dut("configure terminal")
    dut("radius-server host 1.1.1.3 timeout 25")
    dut("end")
    increment_radius_server()
    dump = dut("show radius-server detail")
    lines = dump.splitlines()
    count = 0

    server_params = ("1.1.1.3", DEFAULT_RADIUS_AUTH_PORT,
                      DEFAULT_RADIUS_PASSKEY, "25", DEFAULT_RADIUS_RETRIES,
                      DEFAULT_RADIUS_AUTH_TYPE, DEFAULT_RADIUS_GROUP, str(COUNT_RADIUS_SERVER))
    if server_params == get_radius_server_details(lines, "1.1.1.3"):
        step('\n### server (with valid timeout) present as per show cli - '
                 'passed ###')
        count = count + 1

    ''' now check the running config '''
    dump = dut("show running-config")
    lines = dump.splitlines()
    for line in lines:
        if ("radius-server host 1.1.1.3 timeout 25" in line):
            step('\n### server (with valid timeout) present in running config - '
                 'passed ###')
            count = count + 1

    assert count == 2,\
            '\n### server (with valid timeout) addition test failed ###'

    step('\n### server (with valid timeout) addition test passed ###')
    step('\n### === server (with valid timeout) addition test end === ###\n')

def radius_add_server_with_valid_retries(dut, step):
    step('\n### === server (with valid retries) addition test start === ###')
    dut("configure terminal")
    dut("radius-server host abc.com retries 4")
    dut("end")
    increment_radius_server()
    dump = dut("show radius-server detail")
    lines = dump.splitlines()
    count = 0

    server_params = ("abc.com", DEFAULT_RADIUS_AUTH_PORT,
                      DEFAULT_RADIUS_PASSKEY, DEFAULT_RADIUS_TIMEOUT, "4",
                      DEFAULT_RADIUS_AUTH_TYPE, DEFAULT_RADIUS_GROUP, str(COUNT_RADIUS_SERVER))
    if server_params == get_radius_server_details(lines, "abc.com"):
        step('\n### server (with valid retries) present as per show cli - '
                 'passed ###')
        count = count + 1

    ''' now check the running config '''
    dump = dut("show running-config")
    lines = dump.splitlines()
    for line in lines:
        if ("radius-server host abc.com retries 4" in line):
            step('\n### server (with valid retries) present in running config - '
                 'passed ###')
            count = count + 1

    assert count == 2,\
            '\n### server (with valid retries) addition test failed ###'

    step('\n### server (with valid retries) addition test passed ###')
    step('\n### === server (with valid retries) addition test end === ###\n')


def radius_add_server_with_valid_auth_port(dut, step):
    step('\n### === server (with valid auth port) addition test start === ###')
    dut("configure terminal")
    dut("radius-server host 1.1.1.4 port 45")
    dut("end")
    increment_radius_server()
    dump = dut("show radius-server detail")
    lines = dump.splitlines()
    count = 0

    server_params = ("1.1.1.4", "45",
                      DEFAULT_RADIUS_PASSKEY, DEFAULT_RADIUS_TIMEOUT, DEFAULT_RADIUS_RETRIES,
                      DEFAULT_RADIUS_AUTH_TYPE, DEFAULT_RADIUS_GROUP, str(COUNT_RADIUS_SERVER))
    if server_params == get_radius_server_details(lines, "1.1.1.4"):
        step('\n### server (with valid auth port) present as per show cli - '
                 'passed ###')
        count = count + 1

    ''' now check the running config '''
    dump = dut("show running-config")
    lines = dump.splitlines()
    for line in lines:
        if ("radius-server host 1.1.1.4 port 45" in line):
            step('\n### server (with valid auth port) present in running config - '
                 'passed ###')
            count = count + 1

    assert count == 2,\
            '\n### server (with valid auth port) addition test failed ###'

    step('\n### server (with valid auth port) addition test passed ###')
    step('\n### === server (with valid auth port) addition test end === ###\n')

def radius_add_server_with_valid_auth_type(dut, step):
    step('\n### === server (with valid auth-type) addition test start === ###')
    dut("configure terminal")
    dut("radius-server host 1.1.1.5 auth-type chap")
    dut("end")
    increment_radius_server()
    dump = dut("show radius-server detail")
    lines = dump.splitlines()
    count = 0

    server_params = ("1.1.1.5", DEFAULT_RADIUS_AUTH_PORT,
                      DEFAULT_RADIUS_PASSKEY, DEFAULT_RADIUS_TIMEOUT, DEFAULT_RADIUS_RETRIES,
                      "chap", DEFAULT_RADIUS_GROUP, str(COUNT_RADIUS_SERVER))
    if server_params == get_radius_server_details(lines, "1.1.1.5"):
        step('\n### server (with valid auth-type) present as per show cli - '
                 'passed ###')
        count = count + 1

    ''' now check the running config '''
    dump = dut("show running-config")
    lines = dump.splitlines()
    for line in lines:
        if ("radius-server host 1.1.1.5 auth-type chap" in line):
            step('\n### server (with valid auth-type) present in running config - '
                 'passed ###')
            count = count + 1

    assert count == 2,\
            '\n### server (with valid auth-type) addition test failed ###'

    step('\n### server (with valid auth-type) addition test passed ###')
    step('\n### === server (with valid auth-type) addition test end === ###\n')

def radius_add_server_all_options(dut, step):
    step('\n### === server (with all options) addition test start === ###')
    dut("configure terminal")
    dut("radius-server host 1.1.1.6 key sample-key port 46 retries 3 timeout 20 auth-type chap")
    dut("end")
    increment_radius_server()
    dump = dut("show radius-server detail")
    lines = dump.splitlines()
    count = 0

    server_params = ("1.1.1.6", "46", "sample-key", "20", "3",
                     "chap", DEFAULT_RADIUS_GROUP, str(COUNT_RADIUS_SERVER))
    if server_params == get_radius_server_details(lines, "1.1.1.6"):
        step('\n### server (with all options) present as per show cli - passed ###')
        count = count + 1

    ''' now check the running config '''
    dump = dut("show running-config")
    lines = dump.splitlines()
    for line in lines:
        if ("radius-server host 1.1.1.6 port 46 timeout 20 key sample-key auth-type chap retries 3" in line):
            step('\n### server (with all options) present in running config -'
                 ' passed ###')
            count = count + 1

    assert count == 2,\
            '\n### server (with all options) addition test failed ###'

    step('\n### server (with all options) addition test passed ###')
    step('\n### === server (with all options) addition test end === ###\n')

def radius_add_ipv6_server_all_options(dut, step):
    step('\n### === server (with all options) addition test start === ###')
    dut("configure terminal")
    dut("radius-server host 2001:0db8:85a3:0000:0000:8a2e:0370:7334 key sample-key port 47 timeout 20 auth-type chap retries 4")
    dut("end")
    increment_radius_server()
    dump = dut("show radius-server detail")
    lines = dump.splitlines()
    count = 0

    server_params = ("2001:0db8:85a3:0000:0000:8a2e:0370:7334", "47", "sample-key", "20", "4", "chap", DEFAULT_RADIUS_GROUP, str(COUNT_RADIUS_SERVER))
    if server_params == get_radius_server_details(lines, "2001:0db8:85a3:0000:0000:8a2e:0370:7334"):
        step('\n### server (with all options) present as per show cli - passed ###')
        count = count + 1

    ''' now check the running config '''
    dump = dut("show running-config")
    lines = dump.splitlines()
    for line in lines:
        if ("radius-server host 2001:0db8:85a3:0000:0000:8a2e:0370:7334 port 47 timeout 20 key sample-key auth-type chap retries 4" in line):
            step('\n### server (with all options) present in running config -'
                 ' passed ###')
            count = count + 1

    assert count == 2,\
            '\n### server (with all options) addition test failed ###'

    step('\n### server (with all options) addition test passed ###')
    step('\n### === server (with all options) addition test end === ###\n')

def radius_add_server_with_invalid_server_name(dut, step):
    step('\n### === server (with invalid server name) addition test start '
         '=== ###')
    dut("configure terminal")

    ''' ill-formatted ip addreses '''
    dut("radius-server host 4.4")
    dut("radius-server host 4.5.6.")
    dut("radius-server host 5.5.275.5")

    ''' loopback, multicast,broadcast and experimental ip addresses '''
    dut("radius-server host 127.25.25.25")
    dut("radius-server host 230.25.25.25")
    dut("radius-server host 250.25.25.25")

    ''' ip addresses starting with 0 '''
    dut("radius-server host 0.1.1.1")

    dut("end")
    dump = dut("show radius-server detail")
    lines = dump.splitlines()
    count = 0
    count = count + 1
    for line in lines:
        if (
            "4.4" in line or "4.5.6." in line or "5.5.275.5" in line or
            "127.25.25.25" in line or "230.25.25.25" in line or
            "250.25.25.25" in line or "0.1.1.1" in line
        ):
            '\n### server (with ill-formatted ) present as per show '
            'cli - failed ###'
            count = count - 1

    ''' now check the running config '''
    count = count + 1
    dump = dut("show running-config")
    lines = dump.splitlines()
    for line in lines:
        if (
            "radius-server host 4.4" in line or "radius-server host 4.5.6." in line or
            "radius-server host 5.5.275.5" in line or
            "radius-server host 127.25.25.25" in line or
            "radius-server host 230.25.25.25" in line or
            "radius-server host 250.25.25.25" in line or
            "radius-server host 0.1.1.1" in line
        ):
            '\n### server (with ill-formatted) present in running '
            'config - failed ###'
            count = count - 1

    assert count == 2,\
            '\n### server (with invalid server name) addition test '\
            'failed ###'

    step('\n### server (with invalid server name) addition test passed ###')
    step('\n### === server (with invalid server name) addition test end ==='
         ' ###\n')


def radius_add_server_with_invalid_timeout(dut, step):
    step('\n### === server (with invalid timeout) addition test start === ###')
    dut("configure terminal")
    dut("radius-server host 4.4.4.4 timeout 63")
    dut("radius-server host 4.4.4.5 timeout abc")
    dut("radius-server host 4.4.4.6 timeout  0")
    dut("end")
    dump = dut("show radius-server detail")
    lines = dump.splitlines()
    count = 0
    count = count + 1
    for line in lines:
        if ("4.4.4.4" in line or "4.4.4.5" in line or "4.4.4.6" in line):
            '\n### server (with invalid timeout) present as per '
            'show cli - failed ###'
            count = count - 1

    ''' now check the running config '''
    count = count + 1
    dump = dut("show running-config")
    lines = dump.splitlines()
    for line in lines:
        if ("4.4.4.4" in line or "4.4.4.5" in line or "4.4.4.6" in line):
            '\n### server (with invalid timeout) present in '
            'running config - failed ###'
            count = count - 1

    assert count == 2,\
            '\n### server (with invalid timeout) addition test failed ###'

    step('\n### server (with invalid timeout) addition test passed '
         '###')
    step('\n### === server (with invalid timeout) addition test end '
         '=== ###\n')

def radius_add_server_with_invalid_retries(dut, step):
    step('\n### === server (with invalid retries) addition test start === ###')
    dut("configure terminal")
    dut("radius-server host 4.4.4.4 retries 63")
    dut("radius-server host 4.4.4.5 retries abc")
    dut("radius-server host 4.4.4.6 retries  -3")
    dut("end")
    dump = dut("show radius-server detail")
    lines = dump.splitlines()
    count = 0
    count = count + 1
    for line in lines:
        if ("4.4.4.4" in line or "4.4.4.5" in line or "4.4.4.6" in line):
            '\n### server (with invalid retries) present as per '
            'show cli - failed ###'
            count = count - 1

    ''' now check the running config '''
    count = count + 1
    dump = dut("show running-config")
    lines = dump.splitlines()
    for line in lines:
        if ("4.4.4.4" in line or "4.4.4.5" in line or "4.4.4.6" in line):
            '\n### server (with invalid retries) present in '
            'running config - failed ###'
            count = count - 1

    assert count == 2,\
            '\n### server (with invalid retries) addition test failed ###'

    step('\n### server (with invalid retries) addition test passed '
         '###')
    step('\n### === server (with invalid retries) addition test end '
         '=== ###\n')


def radius_add_server_with_invalid_passkey(dut, step):
    step('\n### === server (with invalid passkey) addition test start === ###')
    dut("configure terminal")
    dut("radius-server host 4.4.4.4 key abcdefghijklmnopqrstuvwxyz1234567")
    dut("end")
    dump = dut("show radius-server detail")
    lines = dump.splitlines()
    count = 0
    count = count + 1
    for line in lines:
        if ("4.4.4.4" in line):
            '\n### server (with invalid passkey) present as per '
            'show cli - failed ###'
            count = count - 1

    ''' now check the running config '''
    count = count + 1
    dump = dut("show running-config")
    lines = dump.splitlines()
    for line in lines:
        if ("4.4.4.4" in line):
            '\n### server (with invalid passkey) present in '
            'running config - failed ###'
            count = count - 1

    assert count == 2,\
            '\n### server (with invalid passkey) addition test failed ###'

    step('\n### server (with invalid passkey) addition test passed '
         '###')
    step('\n### === server (with invalid passkey) addition test end '
         '=== ###\n')


def radius_add_server_with_invalid_auth_port(dut, step):
    step('\n### === server (with invalid auth port) addition test start === ###')
    dut("configure terminal")
    dut("radius-server host 4.4.4.4 port 0")
    dut("radius-server host 4.4.4.5 port abc")
    dut("radius-server host 4.4.4.6 port  65536")
    dut("end")
    dump = dut("show radius-server detail")
    lines = dump.splitlines()
    count = 0
    count = count + 1
    for line in lines:
        if ("4.4.4.4" in line or "4.4.4.5" in line or "4.4.4.6" in line):
            '\n### server (with invalid auth port) present as per '
            'show cli - failed ###'
            count = count - 1

    ''' now check the running config '''
    count = count + 1
    dump = dut("show running-config")
    lines = dump.splitlines()
    for line in lines:
        if ("4.4.4.4" in line or "4.4.4.5" in line or "4.4.4.6" in line):
            '\n### server (with invalid auth port) present in '
            'running config - failed ###'
            count = count - 1

    assert count == 2,\
            '\n### server (with invalid auth port) addition test failed ###'

    step('\n### server (with invalid auth port) addition test passed '
         '###')
    step('\n### === server (with invalid auth port) addition test end '
         '=== ###\n')


def radius_add_server_with_fqdn(dut, step):
    step('\n### === server (with fqdn) addition test start === ###')
    dut("configure terminal")
    dut("radius-server host abc.789.com")
    dut("end")
    increment_radius_server()
    dump = dut("show radius-server detail")
    lines = dump.splitlines()
    count = 0

    server_params = ("abc.789.com", DEFAULT_RADIUS_AUTH_PORT,
                      DEFAULT_RADIUS_PASSKEY, DEFAULT_RADIUS_TIMEOUT, DEFAULT_RADIUS_RETRIES,
                      DEFAULT_RADIUS_AUTH_TYPE, DEFAULT_RADIUS_GROUP, str(COUNT_RADIUS_SERVER))
    if server_params == get_radius_server_details(lines, "abc.789.com"):
        step('\n### server (with fqdn) present as per show cli - passed '
                 '###')
        count = count + 1

    ''' now check the running config '''
    dump = dut("show running-config")
    lines = dump.splitlines()
    for line in lines:
        if ("radius-server host abc.789.com" in line):
            step('\n### server (with fqdn) present in running config - passed'
                 ' ###')
            count = count + 1

    assert count == 2,\
            '\n### server (with fqdn) addition test failed ###'

    step('\n### server (with fqdn) addition test passed ###')
    step('\n### === server (with fqdn) addition test end === ###\n')


def radius_add_more_than_64_servers(dut, step):
    step('\n### === addition of more than 64 servers test start === ###')

    dut("configure terminal")
    for i in range(9, 65):
        dut("radius-server host 1.1.1." + str(i))
        increment_radius_server()

    dump = dut("radius-server host 1.1.1.65")
    assert "Exceeded maximum RADIUS servers support" in dump,\
            '\n### more than 64 server addition test failed ###'

    dut("end")

    dump = dut("show radius-server detail")
    lines = dump.splitlines()
    count = 0
    for line in lines:
        if ("1.1.1.65" in line):
            count = count + 1

    ''' now check the running config '''
    dump = dut("show running-config")
    lines = dump.splitlines()
    for line in lines:
        if ("radius-server host 1.1.1.65" in line):
            count = count + 1

    assert count == 0,\
            '\n### === addition of more than 64 servers test failed ==='\
            ' ###'

    step('\n### === addition of more than 64 servers test passed === ###')
    step('\n### === addition of more than 64 servers test end === ###')


def radius_modify_64th_server(dut, step):
    step('\n### === modifying 64th radius-server test start === ###')
    dut("configure terminal")
    dut("radius-server host 1.1.1.64 key server-64-key")
    dut("end")

    dump = dut("show radius-server detail")
    lines = dump.splitlines()
    count = 0
    for line in lines:
        if ("server-64-key" in line):
            count = count + 1

    ''' check the running config '''
    dump = dut("show running-config")
    lines = dump.splitlines()
    for line in lines:
        if ("server-64-key" in line):
            count = count + 1

    assert count == 2,\
            '\n### === modifying 64th radius-server test failed === ###'

    step('\n### === modifying 64th radius-server test passed'
         ' === ###')
    step('\n### === modifying 64th radius-server test end '
         '=== ###')


def radius_del_server(dut, step):
    step('\n### === server deletion test start === ###')
    dut("configure terminal")
    dut("no radius-server host abc.789.com") # this server was created in radius_add_server_with_fqdn
    dut("end")
    dump = dut("show radius-server detail")
    lines = dump.splitlines()
    count = 0
    count = count + 1
    for line in lines:
        if ("abc.789.com" in line):
           '\n### server still present as per show cli - failed ###'
           count = count - 1

    ''' now check the running config '''
    count = count + 1
    dump = dut("show running-config")
    lines = dump.splitlines()
    for line in lines:
        if ("abc.789.com" in line):
            '\n### server still present in running config - failed ###'
            count = count - 1

    assert count == 2,\
            '\n### server deletion test failed ###'

    step('\n### server deletion test passed ###')
    step('\n### === server deletion test end === ###\n')

def radius_create_server_group(dut, step):
    step('\n### === Create RADIUS groups sg1 sg2 test start === ###')
    dut("configure terminal")
    dut("aaa group server radius sg1")
    dut("aaa group server radius sg2")
    dut("end")
    count = 0

    ''' check the running config '''
    dump = dut("show running-config")
    lines = dump.splitlines()
    for line in lines:
        if ("aaa group server radius sg1" in line or
            "aaa group server radius sg2" in line):
            count = count + 1
    assert count == 2,\
            '\n### Create radius group test failed ###'

    step('\n### Create radius group sg1 sg2 test passed ###')
    step('\n### === Create radius group sg1 sg2 test end === ###\n')

def radius_add_server_to_server_group(dut, step):
    step('\n### === add 4 radius servers to sg1 test start === ###')
    dut("configure terminal")
    dut("aaa group server radius sg1")
    dut("server 1.1.1.1")
    increment_sg1_server()
    dut("server 1.1.1.2")
    increment_sg1_server()
    dut("server 1.1.1.3")
    increment_sg1_server()
    dut("server 1.1.1.4 port 45")
    increment_sg1_server()
    dut("end")
    dump = dut("show aaa server-groups radius")
    lines = dump.splitlines()
    count = 0

    server_params = [('sg1', '1.1.1.1', '1812', '1'),
                     ('sg1', '1.1.1.2', '1812', '2'),
                     ('sg1', '1.1.1.3', '1812', '3'),
                     ('sg1', '1.1.1.4', '45', '4')]

    if server_params == get_radius_server_group_rows(lines, "sg1"):
        step('\n### 4 radius server present in show command - '
                 'passed ###')
        count = count + 1

    ''' now check the running config '''
    dump = dut("show running-config")
    lines = dump.splitlines()
    ''' collect all the RADIUS server in server group sg1 '''
    server_line_index = lines.index("aaa group server radius sg1") + 1
    server_info = lines[server_line_index : server_line_index + COUNT_SG1_SERVER]

    if server_info == ["    server 1.1.1.1", "    server 1.1.1.2",
                       "    server 1.1.1.3", "    server 1.1.1.4 port 45"]:
        step('\n### 4 radius server present in running config - '
                 'passed ###')
        count = count + 1
    assert count == 2,\
            '\n### add 4 radius servers to sg1 test failed ###'

    step('\n### add 4 radius servers to sg1 test passed ###')
    step('\n### === add 4 radius servers to sg1 test end === ###\n')

def radius_add_assigned_server_to_server_group(dut, step):
    step('\n### === add radius server from sg1 to sg2 test start === ###')
    dut("configure terminal")
    dut("aaa group server radius sg2")
    lines = dut("server 1.1.1.3")
    dut("end")
    count = 0

    if "RADIUS server already assigned to a group!" in lines:
        count += 1
    assert count == 1,\
            '\n### add radius server from sg1 to sg2 test failed'\
            ' ###'

    step('\n### add radius server from sg1 to sg2 test passed ###')
    step('\n### === add radius server from sg1 to sg2 test end === ###\n')

def radius_set_global_radius_config(dut, step):
    step('\n### === RADIUS global config test start === ###')
    dut("configure terminal")
    dut("radius-server key global-key")
    dut("radius-server timeout 55")
    dut("radius-server auth-type chap")
    dut("radius-server retries 3")
    dut("end")
    dump = dut("show radius-server detail")
    lines = dump.splitlines()
    count = 0
    global DEFAULT_RADIUS_TIMEOUT, DEFAULT_RADIUS_PASSKEY, DEFAULT_RADIUS_AUTH_TYPE, DEFAULT_RADIUS_RETRIES
    DEFAULT_RADIUS_TIMEOUT = "55"
    DEFAULT_RADIUS_PASSKEY = "global-key"
    DEFAULT_RADIUS_AUTH_TYPE = "chap"
    DEFAULT_RADIUS_RETRIES = "3"

    for line in lines:
        if ("Retries: 3" in line or "Shared-Secret: global-key" in line or "Auth-Type: chap" in line or "Timeout: 55" in line or ""):
            count = count + 1

    ''' now check the running config '''
    dump = dut("show running-config")
    lines = dump.splitlines()
    for line in lines:
        if ("radius-server key global-key" in line or
             "radius-server timeout 55" in line or
             "radius-server auth-type chap" in line or
             "radius-server retries 3" in line):
            count = count + 1

    assert count == 8,\
            '\n### global config test failed ###'

    step('\n### global config test passed ###')
    step('\n### === global config test end === ###\n')

def radius_remove_server_from_server_group(dut, step):
    step('\n### === remove radius server from sg1 test start === ###')
    dut("configure terminal")
    dut("aaa group server radius sg1")
    dut("no server 1.1.1.2")
    dut("end")
    dump = dut("show aaa server-groups radius")
    lines = dump.splitlines()
    count = 0

    server_list = [('sg1', '1.1.1.1', '1812', '1'),
                     ('sg1', '1.1.1.3', '1812', '3'),
                     ('sg1', '1.1.1.4', '45', '4')]

    if server_list == get_radius_server_group_rows(lines, "sg1"):
        step('\n### server 1.1.1.2 not present in sg1 in show command - '
                 'passed ###')
        count = count + 1

    default_params = [('radius(default)', '1.1.1.2', '1812', '2')]
    default_list = get_radius_server_group_rows(lines, "radius(default)")
    if set(default_params).issubset(default_list):
        step('\n### server 1.1.1.2 present in radius (default) in show command - '
                 'passed ###')
        count = count + 1

    ''' now check the running config '''
    dump = dut("show running-config")
    lines = dump.splitlines()
    ''' collect all the RADIUS server in server group sg1 '''
    server_line_index = lines.index("aaa group server radius sg1") + 1
    server_info = lines[server_line_index : server_line_index + COUNT_SG1_SERVER - 1]

    if server_info == ["    server 1.1.1.1", "    server 1.1.1.3",
                       "    server 1.1.1.4 port 45"]:
        step('\n### server 1.1.1.2 not present under sg1 in running config - '
                 'passed ###')
        count = count + 1
    assert count == 3,\
            '\n### remove radius server from sg1 test failed ###'

    step('\n### remove radius server from sg1 test passed ###')
    step('\n### === remove radius server from sg1 test end === ###\n')

def radius_remove_server_group(dut, step):
    step('\n### === remove radius server group sg1 test start === ###')
    dut("configure terminal")
    dut("no aaa group server radius sg1")
    dut("end")
    clear_sg1_server()
    dump = dut("show aaa server-groups radius")
    lines = dump.splitlines()
    count = 0

    server_list = [('radius(default)', '1.1.1.1', '1812', '1'),
                   ('radius(default)', '1.1.1.2', '1812', '2'),
                   ('radius(default)', '1.1.1.3', '1812', '3'),
                   ('radius(default)', '1.1.1.4', '45', '4')]

    default_list = get_radius_server_group_rows(lines, "radius(default)")
    if set(server_list).issubset(default_list):
        step('\n### server group sg1 deletion from show aaa server group radius - passed  ###')
        count = count + 1

    ''' now check the running config '''
    dump = dut("show running-config")
    lines = dump.splitlines()
    for line in lines:
        if ("aaa group server radius sg1" in line):
            '\n### radius server group sg1 present in '
            'running config - failed ###'
            count = count - 1
    assert count == 1,\
            '\n### remove radius server group sg1 test failed ###'

    step('\n### remove radius server group sg1 test passed ###')
    step('\n### === remove radius server group sg1 test end === ###\n')


def test_ct_radius_config(topology, step):
    ops1 = topology.get("ops1")
    assert ops1 is not None

    # please maintain the order of these tests to keep switch in proper state
    radius_add_server_no_options(ops1, step)

    radius_add_server_with_valid_passkey(ops1, step)

    radius_add_server_with_valid_timeout(ops1, step)

    radius_add_server_with_valid_auth_port(ops1, step)

    radius_add_server_with_valid_auth_type(ops1, step)

    radius_add_server_all_options(ops1, step)

    radius_add_ipv6_server_all_options(ops1, step)

    radius_add_server_with_invalid_server_name(ops1, step)

    radius_add_server_with_invalid_passkey(ops1, step)

    radius_add_server_with_invalid_timeout(ops1, step)

    radius_add_server_with_invalid_auth_port(ops1, step)

    radius_add_server_with_valid_retries(ops1, step)

    radius_add_server_with_invalid_retries(ops1, step)

    radius_set_global_radius_config(ops1, step)

    radius_add_server_with_fqdn(ops1, step)

    radius_del_server(ops1, step)

    radius_add_more_than_64_servers(ops1, step)

    radius_modify_64th_server(ops1, step)    # this also verifies update operation

    radius_create_server_group(ops1, step)

    radius_add_server_to_server_group(ops1, step)   #operation depends on radius_add_server_ test cases

    radius_add_assigned_server_to_server_group(ops1, step)

    radius_remove_server_from_server_group(ops1, step)

    radius_remove_server_group(ops1, step)
