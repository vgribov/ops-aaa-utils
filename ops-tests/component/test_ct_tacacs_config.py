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
from pytest import mark

DEFAULT_TACACS_TIMEOUT = "5"
DEFAULT_TACACS_AUTH_PORT = "49"
DEFAULT_TACACS_PASSKEY = "testing123-1"
DEFAULT_TACACS_AUTH_TYPE = "pap"
DEFAULT_TACACS_GROUP = "tacacs_plus"
COUNT_TACACS_SERVER = 0
COUNT_SG1_SERVER = 0
COUNT_SG2_SERVER = 0
CHECK_SUCCESS = 1
CHECK_FAILED = -1

def increment_tacacs_server():
    global COUNT_TACACS_SERVER
    COUNT_TACACS_SERVER = COUNT_TACACS_SERVER + 1

def increment_sg1_server():
    global COUNT_SG1_SERVER
    COUNT_SG1_SERVER = COUNT_SG1_SERVER + 1

def clear_sg1_server():
    global COUNT_SG1_SERVER
    COUNT_SG1_SERVER = 0

def get_tacacs_server_details(lines, server_name):
    lines = [line.strip().replace(' ', '') for line in lines]

    ''' collect all the TACACS+ server details '''
    server_line_index = lines.index("Server-Name:" + server_name)
    server_info = lines[server_line_index : server_line_index + 7]

    ''' collect TACACS+ server parameters
        in format (name, port, key, timeout, auth-type, server-group, default-priority)
    '''
    params = [param.split(":")[-1] for param in server_info]
    if params[0] in server_name:
        params[0] = server_name
    print (params)
    return tuple(params)

def get_tacacs_server_group_rows(lines, sg_name):
    groups = []
    lines = [line.strip().replace(' ', '') for line in lines]

    ''' collect all the TACACS+ server details for specified server group_name '''
    for line in lines:
        if sg_name in line:
            params = line.split("|")
            groups.append(tuple(params))
    print(groups)
    return groups

def check_tacacs_server_group_priority_list(lines, group_list):
    lines = [line.strip().replace(' ', '') for line in lines]
    group_num = len(group_list)
    count = 0
    ''' collect all the TACACS+ server details for specified server group_name '''
    for line in lines:
        server_group = group_list[count]
        if server_group[0] in line:
            params = line.split("|")
            if server_group == tuple(params):
                count = count + 1
    if count == group_num:
        return CHECK_SUCCESS
    return CHECK_FAILED

def tacacs_add_server_no_options(dut, step):
    step('\n### === server (with no options) addition test start === ###')
    dut("configure terminal")
    dut("tacacs-server host 1.1.1.1")
    dut("end")
    increment_tacacs_server()
    dump = dut("show tacacs-server detail")
    lines = dump.splitlines()
    count = 0

    server_params = ("1.1.1.1", DEFAULT_TACACS_AUTH_PORT,
                      DEFAULT_TACACS_PASSKEY, DEFAULT_TACACS_TIMEOUT,
                      DEFAULT_TACACS_AUTH_TYPE, DEFAULT_TACACS_GROUP, str(COUNT_TACACS_SERVER))
    print(server_params)

    if server_params == get_tacacs_server_details(lines, "1.1.1.1"):
        step('\n### server (with no options) present in command - '
                 'passed ###')
        count = count + 1

    ''' now check the running config '''
    dump = dut("show running-config")
    lines = dump.splitlines()
    for line in lines:
        if "tacacs-server host 1.1.1.1" in line:
            step('\n### server (with no options) present in running config - '
                 'passed ###')
            count = count + 1
            print(count)
    assert count == 2,\
            '\n### server (with no options) addition test failed ###'

    step('\n### server (with no options) addition test passed ###')
    step('\n### === server (with no options) addition test end === ###\n')


def tacacs_add_server_with_valid_passkey(dut, step):
    step('\n### === server (with valid passkey) addition test start === ###')
    dut("configure terminal")
    dut("tacacs-server host 1.1.1.2 key test-key")
    dut("end")
    increment_tacacs_server()
    dump = dut("show tacacs-server detail")
    lines = dump.splitlines()
    count = 0

    server_params = ("1.1.1.2", DEFAULT_TACACS_AUTH_PORT,
                     "test-key", DEFAULT_TACACS_TIMEOUT,
                     DEFAULT_TACACS_AUTH_TYPE, DEFAULT_TACACS_GROUP, str(COUNT_TACACS_SERVER))
    if server_params == get_tacacs_server_details(lines, "1.1.1.2"):
        step('\n### server (with valid passkey) present as per show cli - '
                 'passed ###')
        count = count + 1

    ''' now check the running config '''
    dump = dut("show running-config")
    lines = dump.splitlines()
    for line in lines:
        if ("tacacs-server host 1.1.1.2 key test-key" in line):
            step('\n### server (with valid passkey) present in running config - '
                 'passed ###')
            count = count + 1

    assert count == 2,\
            '\n### server (with valid passkey) addition test failed ###'

    step('\n### server (with valid passkey) addition test passed ###')
    step('\n### === server (with valid passkey) addition test end === ###\n')


def tacacs_add_server_with_valid_timeout(dut, step):
    step('\n### === server (with valid timeout) addition test start === ###')
    dut("configure terminal")
    dut("tacacs-server host 1.1.1.3 timeout 25")
    dut("end")
    increment_tacacs_server()
    dump = dut("show tacacs-server detail")
    lines = dump.splitlines()
    count = 0

    server_params = ("1.1.1.3", DEFAULT_TACACS_AUTH_PORT,
                      DEFAULT_TACACS_PASSKEY, "25",
                      DEFAULT_TACACS_AUTH_TYPE, DEFAULT_TACACS_GROUP, str(COUNT_TACACS_SERVER))
    if server_params == get_tacacs_server_details(lines, "1.1.1.3"):
        step('\n### server (with valid timeout) present as per show cli - '
                 'passed ###')
        count = count + 1

    ''' now check the running config '''
    dump = dut("show running-config")
    lines = dump.splitlines()
    for line in lines:
        if ("tacacs-server host 1.1.1.3 timeout 25" in line):
            step('\n### server (with valid timeout) present in running config - '
                 'passed ###')
            count = count + 1

    assert count == 2,\
            '\n### server (with valid timeout) addition test failed ###'

    step('\n### server (with valid timeout) addition test passed ###')
    step('\n### === server (with valid timeout) addition test end === ###\n')


def tacacs_add_server_with_valid_auth_port(dut, step):
    step('\n### === server (with valid auth port) addition test start === ###')
    dut("configure terminal")
    dut("tacacs-server host 1.1.1.4 port 45")
    dut("end")
    increment_tacacs_server()
    dump = dut("show tacacs-server detail")
    lines = dump.splitlines()
    count = 0

    server_params = ("1.1.1.4", "45",
                      DEFAULT_TACACS_PASSKEY, DEFAULT_TACACS_TIMEOUT,
                      DEFAULT_TACACS_AUTH_TYPE, DEFAULT_TACACS_GROUP, str(COUNT_TACACS_SERVER))
    if server_params == get_tacacs_server_details(lines, "1.1.1.4"):
        step('\n### server (with valid auth port) present as per show cli - '
                 'passed ###')
        count = count + 1

    ''' now check the running config '''
    dump = dut("show running-config")
    lines = dump.splitlines()
    for line in lines:
        if ("tacacs-server host 1.1.1.4 port 45" in line):
            step('\n### server (with valid auth port) present in running config - '
                 'passed ###')
            count = count + 1

    assert count == 2,\
            '\n### server (with valid auth port) addition test failed ###'

    step('\n### server (with valid auth port) addition test passed ###')
    step('\n### === server (with valid auth port) addition test end === ###\n')

def tacacs_add_server_with_valid_auth_type(dut, step):
    step('\n### === server (with valid auth-type) addition test start === ###')
    dut("configure terminal")
    dut("tacacs-server host 1.1.1.5 auth-type chap")
    dut("end")
    increment_tacacs_server()
    dump = dut("show tacacs-server detail")
    lines = dump.splitlines()
    count = 0

    server_params = ("1.1.1.5", DEFAULT_TACACS_AUTH_PORT,
                      DEFAULT_TACACS_PASSKEY, DEFAULT_TACACS_TIMEOUT,
                      "chap", DEFAULT_TACACS_GROUP, str(COUNT_TACACS_SERVER))
    if server_params == get_tacacs_server_details(lines, "1.1.1.5"):
        step('\n### server (with valid auth-type) present as per show cli - '
                 'passed ###')
        count = count + 1

    ''' now check the running config '''
    dump = dut("show running-config")
    lines = dump.splitlines()
    for line in lines:
        if ("tacacs-server host 1.1.1.5 auth-type chap" in line):
            step('\n### server (with valid auth-type) present in running config - '
                 'passed ###')
            count = count + 1

    assert count == 2,\
            '\n### server (with valid auth-type) addition test failed ###'

    step('\n### server (with valid auth-type) addition test passed ###')
    step('\n### === server (with valid auth-type) addition test end === ###\n')

def tacacs_add_server_all_options(dut, step):
    step('\n### === server (with all options) addition test start === ###')
    dut("configure terminal")
    dut("tacacs-server host 1.1.1.6 key sample-key port 46 timeout 20 auth-type chap")
    dut("end")
    increment_tacacs_server()
    dump = dut("show tacacs-server detail")
    lines = dump.splitlines()
    count = 0

    server_params = ("1.1.1.6", "46", "sample-key", "20",
                     "chap", DEFAULT_TACACS_GROUP, str(COUNT_TACACS_SERVER))
    if server_params == get_tacacs_server_details(lines, "1.1.1.6"):
        step('\n### server (with all options) present as per show cli - passed ###')
        count = count + 1

    ''' now check the running config '''
    dump = dut("show running-config")
    lines = dump.splitlines()
    for line in lines:
        if ("tacacs-server host 1.1.1.6 port 46 timeout 20 key sample-key auth-type chap" in line):
            step('\n### server (with all options) present in running config -'
                 ' passed ###')
            count = count + 1

    assert count == 2,\
            '\n### server (with all options) addition test failed ###'

    step('\n### server (with all options) addition test passed ###')
    step('\n### === server (with all options) addition test end === ###\n')

def tacacs_add_ipv6_server_all_options(dut, step):
    step('\n### === server (with all options) addition test start === ###')
    dut("configure terminal")
    dut("tacacs-server host 2001:0db8:85a3:0000:0000:8a2e:0370:7334 key sample-key port 47 timeout 20 auth-type chap")
    dut("end")
    increment_tacacs_server()
    dump = dut("show tacacs-server detail")
    lines = dump.splitlines()
    count = 0

    server_params = ("2001:0db8:85a3:0000:0000:8a2e:0370:7334", "47", "sample-key", "20",
                     "chap", DEFAULT_TACACS_GROUP, str(COUNT_TACACS_SERVER))
    if server_params == get_tacacs_server_details(lines, "2001:0db8:85a3:0000:0000:8a2e:0370:7334"):
        step('\n### server (with all options) present as per show cli - passed ###')
        count = count + 1

    ''' now check the running config '''
    dump = dut("show running-config")
    lines = dump.splitlines()
    for line in lines:
        if ("tacacs-server host 2001:0db8:85a3:0000:0000:8a2e:0370:7334 port 47 timeout 20 key sample-key auth-type chap" in line):
            step('\n### server (with all options) present in running config -'
                 ' passed ###')
            count = count + 1

    assert count == 2,\
            '\n### server (with all options) addition test failed ###'

    step('\n### server (with all options) addition test passed ###')
    step('\n### === server (with all options) addition test end === ###\n')

def tacacs_add_server_with_invalid_server_name(dut, step):
    step('\n### === server (with invalid server name) addition test start '
         '=== ###')
    dut("configure terminal")

    ''' ill-formatted ip addreses '''
    dut("tacacs-server host 4.4")
    dut("tacacs-server host 4.5.6.")
    dut("tacacs-server host 5.5.275.5")

    ''' loopback, multicast,broadcast and experimental ip addresses '''
    dut("tacacs-server host 127.25.25.25")
    dut("tacacs-server host 230.25.25.25")
    dut("tacacs-server host 250.25.25.25")

    ''' ip addresses starting with 0 '''
    dut("tacacs-server host 0.1.1.1")

    dut("end")
    dump = dut("show tacacs-server detail")
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
            "tacacs-server host 4.4" in line or "tacacs-server host 4.5.6." in line or
            "tacacs-server host 5.5.275.5" in line or
            "tacacs-server host 127.25.25.25" in line or
            "tacacs-server host 230.25.25.25" in line or
            "tacacs-server host 250.25.25.25" in line or
            "tacacs-server host 0.1.1.1" in line
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


def tacacs_add_server_with_invalid_timeout(dut, step):
    step('\n### === server (with invalid timeout) addition test start === ###')
    dut("configure terminal")
    dut("tacacs-server host 4.4.4.4 timeout 63")
    dut("tacacs-server host 4.4.4.5 timeout abc")
    dut("tacacs-server host 4.4.4.6 timeout  0")
    dut("end")
    dump = dut("show tacacs-server detail")
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


def tacacs_add_server_with_invalid_passkey(dut, step):
    step('\n### === server (with invalid passkey) addition test start === ###')
    dut("configure terminal")
    dut("tacacs-server host 4.4.4.4 key abcdefghijklmnopqrstuvwxyz1234567")
    dut("end")
    dump = dut("show tacacs-server detail")
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


def tacacs_add_server_with_invalid_auth_port(dut, step):
    step('\n### === server (with invalid auth port) addition test start === ###')
    dut("configure terminal")
    dut("tacacs-server host 4.4.4.4 port 0")
    dut("tacacs-server host 4.4.4.5 port abc")
    dut("tacacs-server host 4.4.4.6 port  65536")
    dut("end")
    dump = dut("show tacacs-server detail")
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


def tacacs_add_server_with_fqdn(dut, step):
    step('\n### === server (with fqdn) addition test start === ###')
    dut("configure terminal")
    dut("tacacs-server host abc.789.com")
    dut("end")
    increment_tacacs_server()
    dump = dut("show tacacs-server detail")
    lines = dump.splitlines()
    count = 0

    server_params = ("abc.789.com", DEFAULT_TACACS_AUTH_PORT,
                      DEFAULT_TACACS_PASSKEY, DEFAULT_TACACS_TIMEOUT,
                      DEFAULT_TACACS_AUTH_TYPE, DEFAULT_TACACS_GROUP, str(COUNT_TACACS_SERVER))
    if server_params == get_tacacs_server_details(lines, "abc.789.com"):
        step('\n### server (with fqdn) present as per show cli - passed '
                 '###')
        count = count + 1

    ''' now check the running config '''
    dump = dut("show running-config")
    lines = dump.splitlines()
    for line in lines:
        if ("tacacs-server host abc.789.com" in line):
            step('\n### server (with fqdn) present in running config - passed'
                 ' ###')
            count = count + 1

    assert count == 2,\
            '\n### server (with fqdn) addition test failed ###'

    step('\n### server (with fqdn) addition test passed ###')
    step('\n### === server (with fqdn) addition test end === ###\n')


def tacacs_add_server_with_long_server_name(dut, step):
    step('\n### === server (with long server name) addition test start === '
         '###')
    dut("configure terminal")
    count = 0

    ''' long server name '''
    lines = dut("tacacs-server host vabcdefghijklmnopqrstuvwxyzeabcdefghijklmnopqr")
    if "Server name should be less than 45 characters" in lines:
        count += 1
    assert count == 1,\
            '\n###  server (with max chars with server name) addition test failed'\
            ' ###'

    dut("end")

    dump = dut("show tacacs-server detail")
    lines = dump.splitlines()
    for line in lines:
        if ("vabcdefghijklmnopqrstuvwxyzeabcdefghijklmnopqr" in line):
            count = count + 1

    dump = dut("show running-config")
    lines = dump.splitlines()
    for line in lines:
        if ("vabcdefghijklmnopqrstuvwxyzeabcdefghijklmnopqr" in line):
            count = count + 1

    assert count == 1,\
            '\n###  server (with long server name) addition test failed'\
            ' ###'

    step('\n### server (with long server name) addition test passed ###')
    step('\n### === server (with long server name) addition test end === ###'
         '\n')


def tacacs_add_more_than_64_servers(dut, step):
    step('\n### === addition of more than 64 servers test start === ###')

    dut("configure terminal")
    for i in range(8, 65):
        dut("tacacs-server host 1.1.1." + str(i))
        increment_tacacs_server()

    dump = dut("tacacs-server host 1.1.1.65")
    assert "Exceeded maximum TACACS+ servers support" in dump,\
            '\n### more than 64 server addition test failed ###'

    dut("end")

    dump = dut("show tacacs-server detail")
    lines = dump.splitlines()
    count = 0
    for line in lines:
        if ("1.1.1.65" in line):
            count = count + 1

    ''' now check the running config '''
    dump = dut("show running-config")
    lines = dump.splitlines()
    for line in lines:
        if ("tacacs-server host 1.1.1.65" in line):
            count = count + 1

    assert count == 0,\
            '\n### === addition of more than 64 servers test failed ==='\
            ' ###'

    step('\n### === addition of more than 64 servers test passed === ###')
    step('\n### === addition of more than 64 servers test end === ###')


def tacacs_modify_64th_server(dut, step):
    step('\n### === modifying 64th tacacs-server test start === ###')
    dut("configure terminal")
    dut("tacacs-server host 1.1.1.64 key server-64-key")
    dut("end")

    dump = dut("show tacacs-server detail")
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
            '\n### === modifying 64th tacacs-server test failed === ###'

    step('\n### === modifying 64th tacacs-server test passed'
         ' === ###')
    step('\n### === modifying 64th tacacs-server test end '
         '=== ###')


def tacacs_del_server(dut, step):
    step('\n### === server deletion test start === ###')
    dut("configure terminal")
    dut("no tacacs-server host abc.789.com") # this server was created in tacacs_add_server_with_fqdn
    dut("end")
    dump = dut("show tacacs-server detail")
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


def tacacs_set_global_tacacs_config(dut, step):
    step('\n### === TACACS+ global config test start === ###')
    dut("configure terminal")
    dut("tacacs-server key global-key")
    dut("tacacs-server timeout 55")
    dut("tacacs-server auth-type chap")
    dut("end")
    dump = dut("show tacacs-server detail")
    lines = dump.splitlines()
    count = 0
    global DEFAULT_TACACS_TIMEOUT, DEFAULT_TACACS_PASSKEY, DEFAULT_TACACS_AUTH_TYPE
    DEFAULT_TACACS_TIMEOUT = "55"
    DEFAULT_TACACS_PASSKEY = "global-key"
    DEFAULT_TACACS_AUTH_TYPE = "chap"

    for line in lines:
        if ("Shared-Secret: global-key" in line or "Auth-Type: chap" in line or
             "Timeout: 55" in line or ""):
            count = count + 1

    ''' now check the running config '''
    dump = dut("show running-config")
    lines = dump.splitlines()
    for line in lines:
        if ("tacacs-server key global-key" in line or
             "tacacs-server timeout 55" in line or
             "tacacs-server auth-type chap" in line):
            count = count + 1

    assert count == 6,\
            '\n### global config test failed ###'

    step('\n### global config test passed ###')
    step('\n### === global config test end === ###\n')


def tacacs_create_server_group(dut, step):
    step('\n### === Create tacacs+ groups sg1 sg2 test start === ###')
    dut("configure terminal")
    dut("aaa group server tacacs+ sg1")
    dut("aaa group server tacacs+ sg2")
    dut("end")
    count = 0

    ''' check the running config '''
    dump = dut("show running-config")
    lines = dump.splitlines()
    for line in lines:
        if ("aaa group server tacacs+ sg1" in line or
            "aaa group server tacacs+ sg2" in line):
            count = count + 1
    assert count == 2,\
            '\n### Create tacacs+ group sg1 test failed ###'

    step('\n### Create tacacs+ group sg1 sg2 test passed ###')
    step('\n### === Create tacacs+ group sg1 sg2 test end === ###\n')

def tacacs_add_server_to_server_group(dut, step):
    step('\n### === add 4 tacacs+ servers to sg1 test start === ###')
    dut("configure terminal")
    dut("aaa group server tacacs+ sg1")
    dut("server 1.1.1.1")
    increment_sg1_server()
    dut("server 1.1.1.2")
    increment_sg1_server()
    dut("server 1.1.1.3")
    increment_sg1_server()
    dut("server 1.1.1.4 port 45")
    increment_sg1_server()
    dut("end")
    dump = dut("show aaa server-groups")
    lines = dump.splitlines()
    count = 0

    server_params = [('sg1', '1.1.1.1', '49', '1'),
                     ('sg1', '1.1.1.2', '49', '2'),
                     ('sg1', '1.1.1.3', '49', '3'),
                     ('sg1', '1.1.1.4', '45', '4')]

    if server_params == get_tacacs_server_group_rows(lines, "sg1"):
        step('\n### 4 tacacs+ server present in show command - '
                 'passed ###')
        count = count + 1

    ''' now check the running config '''
    dump = dut("show running-config")
    lines = dump.splitlines()
    ''' collect all the TACACS+ server in server group sg1 '''
    server_line_index = lines.index("aaa group server tacacs+ sg1") + 1
    server_info = lines[server_line_index : server_line_index + COUNT_SG1_SERVER]

    if server_info == ["    server 1.1.1.1", "    server 1.1.1.2",
                       "    server 1.1.1.3", "    server 1.1.1.4 port 45"]:
        step('\n### 4 tacacs+ server present in running config - '
                 'passed ###')
        count = count + 1
    assert count == 2,\
            '\n### add 4 tacacs+ servers to sg1 test failed ###'

    step('\n### add 4 tacacs+ servers to sg1 test passed ###')
    step('\n### === add 4 tacacs+ servers to sg1 test end === ###\n')

def tacacs_add_assigned_server_to_server_group(dut, step):
    step('\n### === add tacacs+ server from sg1 to sg2 test start === ###')
    dut("configure terminal")
    dut("aaa group server tacacs+ sg2")
    lines = dut("server 1.1.1.3")
    dut("end")
    count = 0

    if "TACACS+ server already assigned to a group!" in lines:
        count += 1
    assert count == 1,\
            '\n### add tacacs+ server from sg1 to sg2 test failed'\
            ' ###'

    step('\n### add tacacs+ server from sg1 to sg2 test passed ###')
    step('\n### === add tacacs+ server from sg1 to sg2 test end === ###\n')

def tacacs_remove_server_from_server_group(dut, step):
    step('\n### === remove tacacs+ server from sg1 test start === ###')
    dut("configure terminal")
    dut("aaa group server tacacs+ sg1")
    dut("no server 1.1.1.2")
    dut("end")
    dump = dut("show aaa server-groups")
    lines = dump.splitlines()
    count = 0

    server_list = [('sg1', '1.1.1.1', '49', '1'),
                     ('sg1', '1.1.1.3', '49', '3'),
                     ('sg1', '1.1.1.4', '45', '4')]

    if server_list == get_tacacs_server_group_rows(lines, "sg1"):
        step('\n### server 1.1.1.2 not present in sg1 in show command - '
                 'passed ###')
        count = count + 1

    default_params = [('tacacs_plus(default)', '1.1.1.2', '49', '2')]
    default_list = get_tacacs_server_group_rows(lines, "tacacs_plus(default)")
    if set(default_params).issubset(default_list):
        step('\n### server 1.1.1.2 present in tacacs_plus (default) in show command - '
                 'passed ###')
        count = count + 1

    ''' now check the running config '''
    dump = dut("show running-config")
    lines = dump.splitlines()
    ''' collect all the TACACS+ server in server group sg1 '''
    server_line_index = lines.index("aaa group server tacacs+ sg1") + 1
    server_info = lines[server_line_index : server_line_index + COUNT_SG1_SERVER - 1]

    if server_info == ["    server 1.1.1.1", "    server 1.1.1.3",
                       "    server 1.1.1.4 port 45"]:
        step('\n### server 1.1.1.2 not present under sg1 in running config - '
                 'passed ###')
        count = count + 1
    assert count == 3,\
            '\n### remove tacacs+ server from sg1 test failed ###'

    step('\n### remove tacacs+ server from sg1 test passed ###')
    step('\n### === remove tacacs+ server from sg1 test end === ###\n')

def tacacs_remove_server_group(dut, step):
    step('\n### === remove tacacs+ server group sg1 test start === ###')
    dut("configure terminal")
    dut("no aaa group server tacacs+ sg1")
    dut("end")
    clear_sg1_server()
    dump = dut("show aaa server-groups")
    lines = dump.splitlines()
    count = 0

    server_list = [('tacacs_plus(default)', '1.1.1.1', '49', '1'),
                   ('tacacs_plus(default)', '1.1.1.2', '49', '2'),
                   ('tacacs_plus(default)', '1.1.1.3', '49', '3'),
                   ('tacacs_plus(default)', '1.1.1.4', '45', '4')]

    default_list = get_tacacs_server_group_rows(lines, "tacacs_plus(default)")
    if set(server_list).issubset(default_list):
        step('\n### previously sg1 servers present in tacacs_plus (default) in show command - '
                 'passed ###')
        count = count + 1

    ''' now check the running config '''
    dump = dut("show running-config")
    lines = dump.splitlines()
    ''' collect all the TACACS+ server in server group sg1 '''
    for line in lines:
        if ("aaa group server tacacs+ sg1" in line):
            '\n### tacacs+ server group sg1 present in '
            'running config - failed ###'
            count = count - 1
    assert count == 1,\
            '\n### remove tacacs+ server group sg1 test failed ###'

    step('\n### remove tacacs+ server group sg1 test passed ###')
    step('\n### === remove tacacs+ server group sg1 test end === ###\n')

def set_aaa_authentication_groups(dut, step):
    step('\n### === set aaa authentication groups test start === ###')
    dut("configure terminal")
    dut("aaa authentication login default group sg2 tacacs_plus local")
    dut("end")
    dump = dut("show aaa authentication")
    lines = dump.splitlines()
    count = 0

    group_list = [('sg2', '1'), ('tacacs_plus', '2'), ('local', '3')]

    count = count + check_tacacs_server_group_priority_list(lines, group_list)

    ''' now check the running config '''
    dump = dut("show running-config")
    lines = dump.splitlines()
    for line in lines:
        if ("aaa authentication login default group sg2 tacacs_plus local" in line):
            count = count + 1
    assert count == 2,\
            '\n### set aaa authentication groups test failed ###'

    step('\n### set aaa authentication groups test passed ###')
    step('\n### === set aaa authentication groups test end === ###\n')

def unset_aaa_authentication_groups(dut, step):
    step('\n### === unset aaa authentication groups test start === ###')
    dut("configure terminal")
    dut("no aaa authentication login default")
    dut("end")
    dump = dut("show aaa authentication")
    lines = dump.splitlines()
    count = 0

    group_list = [('local', '0')]

    count = count + check_tacacs_server_group_priority_list(lines, group_list)

    ''' now check the running config '''
    dump = dut("show running-config")
    lines = dump.splitlines()
    for line in lines:
        if ("aaa authentication login default" in line):
            count = count - 1
    assert count == 1,\
            '\n### unset aaa authentication groups test failed ###'

    step('\n### unset aaa authentication groups test passed ###')
    step('\n### === unset aaa authentication groups test end === ###\n')

def set_aaa_authentication_local(dut, step):
    step('\n### === set aaa authentication local test start === ###')
    dut("configure terminal")
    dut("aaa authentication login default local")
    dut("end")
    dump = dut("show aaa authentication")
    lines = dump.splitlines()
    count = 0

    group_list = [('local', '1')]

    count = count + check_tacacs_server_group_priority_list(lines, group_list)

    ''' now check the running config '''
    dump = dut("show running-config")
    lines = dump.splitlines()
    for line in lines:
        if ("aaa authentication login default local" in line):
            count = count + 1
    assert count == 2,\
            '\n### set aaa authentication local test failed ###'

    step('\n### set aaa authentication local test passed ###')
    step('\n### === set aaa authentication local test end === ###\n')

@mark.skipif(True, reason="Disabling as AAA feature revamp in progress")
def test_ct_tacacs_config(topology, step):
    ops1 = topology.get("ops1")
    assert ops1 is not None

    # please maintain the order of these tests to keep switch in proper state
    tacacs_add_server_no_options(ops1, step)

    tacacs_add_server_with_valid_passkey(ops1, step)

    tacacs_add_server_with_valid_timeout(ops1, step)

    tacacs_add_server_with_valid_auth_port(ops1, step)

    tacacs_add_server_with_valid_auth_type(ops1, step)

    tacacs_add_server_all_options(ops1, step)

    tacacs_add_ipv6_server_all_options(ops1, step)

    tacacs_add_server_with_invalid_server_name(ops1, step)

    tacacs_add_server_with_invalid_passkey(ops1, step)

    tacacs_add_server_with_invalid_timeout(ops1, step)

    tacacs_add_server_with_invalid_auth_port(ops1, step)

    tacacs_add_server_with_long_server_name(ops1, step)

    tacacs_set_global_tacacs_config(ops1, step)

    tacacs_add_server_with_fqdn(ops1, step)

    tacacs_del_server(ops1, step)

    tacacs_add_more_than_64_servers(ops1, step)

    tacacs_modify_64th_server(ops1, step)    # this also verifies update operation

    tacacs_create_server_group(ops1, step)

    tacacs_add_server_to_server_group(ops1, step)   #operation depends on tacacs_add_server_ test cases

    tacacs_add_assigned_server_to_server_group(ops1, step)

    tacacs_remove_server_from_server_group(ops1, step)

    tacacs_remove_server_group(ops1, step)

    set_aaa_authentication_groups(ops1, step)

    unset_aaa_authentication_groups(ops1, step)

    set_aaa_authentication_local(ops1, step)
