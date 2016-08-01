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

DEFAULT_TACACS_TIMEOUT = "5"
DEFAULT_TACACS_AUTH_PORT = "49"
DEFAULT_TACACS_PASSKEY = "testing123-1"


def get_tacacs_server_details(lines, server_name):
    lines = [line.strip().replace("\t","") for line in lines]

    ''' collect all the TACACS+ server details '''
    server_line_index = lines.index("Server name: " + server_name)
    server_info = lines[server_line_index : server_line_index + 4]

    ''' collect TACACS+ server parameters
        in format (name, port, key, timeout)
    '''
    params = [param.split(": ")[-1] for param in server_info]
    print (params)
    return tuple(params)


def tacacs_add_server_no_options(dut, step):
    step('\n### === server (with no options) addition test start === ###')
    dut("configure terminal")
    dut("tacacs-server host 1.1.1.1")
    dut("end")
    dump = dut("show tacacs-server detail")
    lines = dump.splitlines()
    count = 0

    server_params = ("1.1.1.1", DEFAULT_TACACS_AUTH_PORT,
            DEFAULT_TACACS_PASSKEY, DEFAULT_TACACS_TIMEOUT)
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
    dump = dut("show tacacs-server detail")
    lines = dump.splitlines()
    count = 0

    server_params = ("1.1.1.2", DEFAULT_TACACS_AUTH_PORT,
            "test-key", DEFAULT_TACACS_TIMEOUT)
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
    dump = dut("show tacacs-server detail")
    lines = dump.splitlines()
    count = 0

    server_params = ("1.1.1.3", DEFAULT_TACACS_AUTH_PORT,
            DEFAULT_TACACS_PASSKEY, "25")
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
    dump = dut("show tacacs-server detail")
    lines = dump.splitlines()
    count = 0

    server_params = ("1.1.1.4", "45", DEFAULT_TACACS_PASSKEY,
            DEFAULT_TACACS_TIMEOUT)
    if server_params == get_tacacs_server_details(lines, "1.1.1.4"):
        step('\n### server (with valid auth port) present as per show cl1i - '
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

def tacacs_add_server_all_options(dut, step):
    step('\n### === server (with all options) addition test start === ###')
    dut("configure terminal")
    dut("tacacs-server host 1.1.1.5 key sample-key port 46 timeout 20")
    dut("end")
    dump = dut("show tacacs-server detail")
    lines = dump.splitlines()
    count = 0

    server_params = ("1.1.1.5", "46", "sample-key", "20")
    if server_params == get_tacacs_server_details(lines, "1.1.1.5"):
        step('\n### server (with all options) present as per show cli - passed ###')
        count = count + 1

    ''' now check the running config '''
    dump = dut("show running-config")
    lines = dump.splitlines()
    for line in lines:
        if ("tacacs-server host 1.1.1.5 port 46 timeout 20 key sample-key" in line):
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
    dut("tacacs-server host 4.4.4.4 passkey MBsaIbrZR5PIG4gfgNHrHPHHMJRhz3IVXYp4oLlf7gKacEhZTXKU980jEZsXo9u5")
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
    dump = dut("show tacacs-server detail")
    lines = dump.splitlines()
    count = 0

    server_params = ("abc.789.com", "121", "global-key", "55")
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
    lines = dut("tacacs-server host vabcdefghijklmnopqrstuvwxyzeabcdefghijklmnopqrstuvwxyzrabcdefghijklmnopqrstuvwxy")
    if "Server name should be less than 58 characters" in lines:
        count += 1
    assert count == 1,\
            '\n###  server (with max chars with server name) addition test failed'\
            ' ###'

    dut("end")

    dump = dut("show tacacs-server detail")
    lines = dump.splitlines()
    for line in lines:
        if ("vabcdefghijklmnopqrstuvwxyzeabcdefghijklmnopqrstuvwxyzrabcdefghijklmnopqrstuvwxy" in line):
            count = count + 1

    dump = dut("show running-config")
    lines = dump.splitlines()
    for line in lines:
        if ("vabcdefghijklmnopqrstuvwxyzeabcdefghijklmnopqrstuvwxyzrabcdefghijklmnopqrstuvwxy" in line):
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
    for i in range(1, 65):
        dut("tacacs-server host 1.1.1." + str(i))

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
    dut("tacacs-server port 121")
    dut("end")
    dump = dut("show tacacs-server detail")
    lines = dump.splitlines()
    count = 0
    for line in lines:
        if ("Shared secret: global-key" in line or "Auth port: 121" in line or
                "Timeout: 55" in line):
               count = count + 1

    ''' now check the running config '''
    dump = dut("show running-config")
    lines = dump.splitlines()
    for line in lines:
        if ("tacacs-server key global-key" in line or
                "tacacs-server port 121" in line or
                "tacacs-server timeout 55" in line):
            count = count + 1

    assert count == 6,\
            '\n### global config test failed ###'

    step('\n### global config test passed ###')
    step('\n### === global config test end === ###\n')



def test_ct_tacacs_config(topology, step):
    ops1 = topology.get("ops1")
    assert ops1 is not None

    # please maintain the order of these tests to keep switch in proper state
    tacacs_add_server_no_options(ops1, step)

    tacacs_add_server_with_valid_passkey(ops1, step)

    tacacs_add_server_with_valid_timeout(ops1, step)

    tacacs_add_server_with_valid_auth_port(ops1, step)

    tacacs_add_server_all_options(ops1, step)

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
