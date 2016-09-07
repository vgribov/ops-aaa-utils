#!/usr/bin/env python

# Copyright (C) 2015 Hewlett Packard Enterprise Development LP
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

from pytest import mark

from time import sleep
from re import escape

TOPOLOGY = """
# +-------+          +-------+
# |       |          |       |
# |  s1   <---------->   s2  |
# |       |          |       |
# +-------+          +-------+

# Nodes
[type=openswitch name="Switch 1"] ops1
[type=openswitch name="Switch 2"] ops2
[type=oobmhost name="Host 1"] hs1
[type=oobmhost name="Host 2"] hs2

# Ports
[force_name=oobm] ops1:sp1
[force_name=oobm] ops2:sp1

# Links
hs1:if01 -- ops1:sp1
hs2:if01 -- ops2:sp1
"""


def get_switch_ip(switch):
    switch_ip = switch("python -c \"import socket; \
                       print socket.gethostbyname(socket.gethostname())\"",
                       shell='bash')
    switch_ip = switch_ip.rstrip("\r\n")
    return switch_ip


def sftp_server_config_test(s1, cond):
    """
    Enable/Disable SFTP server
    Description : Enable/Disable SFTP server based on the
                  condition and verify the status of server
                  using show command
    """

    dut01 = s1
    condition = cond

    dut01("configure terminal")

    if condition is True:
        # Enable SFTP server
        dut01("sftp server enable")
        dut01("end")
        output = dut01("show running-config")
        assert "enable" in output, \
               "Enable SFTP server - FAIL"
        print("Enable SFTP server - SUCCESS")
    else:
        # Disable SFTP server
        dut01("no sftp server enable")
        dut01("end")
        output = dut01("show running-config")
        assert "enable" not in output, \
               "Disable SFTP server - FAIL"
        print("Disable SFTP server - SUCCESS")

    dut01("end")


def sftp_client_get(s1, s2):
    """
    Test to verify SFTP client get
    Description : Use one switch as SFTP server and download a
                  file from server using a get command and
                  verify this operation by looking for the
                  downloaded file in the client and if found,
                  delete this downloaded file
    """
    print("\n############################################\n")
    print("Verify SFTP client get")
    print("\n############################################\n")

    switch1 = s1
    switch2 = s2

    opsuccess = False
    copy = "copy sftp"
    username = "root"
    srcpath = "/etc/ssh/sshd_config"
    destpath = "/home/admin/"
    destfile = "trial_file"

    # Enable SFTP server on SW2
    print("Enabling SFTP server on switch2")
    sftp_server_config_test(switch2, True)

    hostip = get_switch_ip(switch2)
    cmd = copy + " " + username + " " + hostip + \
        " " + srcpath + " " + destpath + destfile
    vtysh_shell = switch1.get_shell("vtysh")
    vtysh_shell.send_command(cmd, matches=escape("Are you sure you want to "
                                                 "continue connecting "
                                                 "(yes/no)? "))

    vtysh_shell.send_command("yes", matches="(^|\n)switch(\\([\\-a-zA-Z0-9]"
                                            "*\\))?#")

    cmd1 = "ls " + destpath + destfile
    out = switch1(cmd1, shell="bash")

    if destpath + destfile in out and \
       "No such file" not in out:
        opsuccess = True
        print("Downloaded file found")
        cmd2 = "rm -rf " + destpath + destfile
        switch1(cmd2, shell="bash")
        print("Downloaded file clean up - SUCCESS")
        print("Verification of SFTP get operation - SUCCESS")

    assert opsuccess is True, \
        "\n SFTP client get - FAILED\n"
    print("\n SFTP client get - PASSED\n")


def sftp_client_int(s1, s2):
    """
    Test the SFTP client interactive mode
    Description : Use one switch as SFTP server and download a
                  file from server using a interactive get command
                  and verify this operation by looking for the
                  downloaded file in the client and if found,
                  delete this downloaded file. Upload a file
                  from client to the server using interactive put
                  verify this operation by looking for the uploaded
                  file and if found, delete this uploaded file
    """
    print("\n############################################\n")
    print("Verify SFTP interactive client")
    print("\n############################################\n")

    switch1 = s1
    switch2 = s2

    opsuccess = False
    copy = "copy sftp"
    username = "root"
    srcpath = "/etc/ssh/sshd_config"
    destpath = "/home/admin/"
    destfile = "trial_file"
    hostip = get_switch_ip(switch2)

    # Interactive mode - get operation
    cmd = copy + " " + username + " " + hostip
    vtysh_shell = switch1.get_shell("vtysh")
    vtysh_shell.send_command(cmd, matches=escape("sftp> "))
    sleep(1)

    # Perform get operation
    getcmd = "get" + " " + srcpath + " " + destpath + destfile
    vtysh_shell.send_command(getcmd, matches=escape("sftp> "))
    sleep(1)

    vtysh_shell.send_command("quit", matches="(^|\n)switch(\\([\\-a-zA-Z0-9]"
                                             "*\\))?#")

    cmd1 = "ls " + destpath + destfile
    out = switch1(cmd1, shell="bash")

    if destpath + destfile in out and \
       "No such file" not in out:
        opsuccess = True
        print("Downloaded file found")
        cmd2 = "rm -rf " + destpath + destfile
        switch1(cmd2, shell="bash")
        print("Downloaded file clean up - SUCCESS")
        print("Verification of interactive SFTP "
              "get operation - SUCCESS")

    assert opsuccess is True, \
        "\n SFTP client interactive get - FAILED\n"
    print("\n SFTP client interactive get - PASSED\n")

    # Interactive mode - put operation
    opsuccess = False
    cmd = copy + " " + username + " " + hostip
    vtysh_shell.send_command(cmd, matches=escape("sftp> "))
    sleep(1)

    # Perform put operation
    putcmd = "put" + " " + srcpath + " " + destpath + destfile
    vtysh_shell.send_command(putcmd, matches=escape("sftp> "))
    sleep(1)

    vtysh_shell.send_command("quit", matches="(^|\n)switch(\\([\\-a-zA-Z0-9]"
                                             "*\\))?#")

    cmd1 = "ls " + destpath + destfile
    out = switch2(cmd1, shell="bash")

    if destpath + destfile in out and \
       "No such file" not in out:
        opsuccess = True
        print("Uploaded file found")
        cmd2 = "rm -rf " + destpath + destfile
        switch2(cmd2, shell="bash")
        print("Uploaded file clean up - SUCCESS")
        print("Verification of interactive SFTP "
              "put operation - SUCCESS")

    assert opsuccess is True, \
        "\n SFTP client interactive put - FAILED\n"
    print("\n SFTP client interactive put - PASSED\n")


def sftp_post_server_disable(s1, s2):
    """
    Test to verify SFTP functionality post server disable
    Description : This is a neagative test scenario disable SFTP server
                  and download a file from server using a get command
                  this copy should not be possible
    """
    print("\n############################################\n")
    print("Verify SFTP functionality post server disable")
    print("\n############################################\n")

    switch1 = s1
    switch2 = s2

    copy = "copy sftp"
    username = "root"
    hostip = get_switch_ip(switch2)
    srcpath = "/etc/ssh/sshd_config"
    destpath = "/home/admin/"
    destfile = "trial_file"
    failmsg = "Connection reset by peer"

    # Disable SFTP server on SW2
    print("Disable SFTP server on switch2")
    sftp_server_config_test(switch2, False)

    # Perform SFTP operation on SW1
    cmd = copy + " " + username + " " + hostip + \
        " " + srcpath + " " + destpath + destfile
    out = switch1(cmd)

    assert failmsg in out, \
        "Verify SFTP get after SFTP server disable - FAILED"
    print("Verify SFTP get after SFTP server disable - SUCCESS")


def sftp_fail_cases(s1, s2):
    """
    Test to verify negative scenarios
    Description : Verify the negative scenarios when user source
                  path of the file is invalid and when destination
                  path is invalid
    """
    print("\n############################################\n")
    print("Verify SFTP negative test cases")
    print("\n############################################\n")

    switch1 = s1
    switch2 = s2

    # opsuccess = False
    copy = "copy sftp"
    username = "root"
    hostip = get_switch_ip(switch2)
    srcpath = "/etc/ssh/sshd_config"
    destpath = "/home/admin/"
    destfile = "trial_file"
    invalidsrcpath = "/invalid/src_path"
    srcfailmsg = "not found"
    invaliddestpath = "/invalid/dest_file"
    destfailmsg = "No such file or directory"

    # Enable SFTP server on SW2
    print("Enable SFTP server on switch2")
    sftp_server_config_test(switch2, True)

    # Invalid source path test
    cmd = copy + " " + username + " " + hostip + " " + \
        invalidsrcpath + " " + destpath + destfile
    out = switch1(cmd)

    assert srcfailmsg in out, \
        "Verify invalid source path test - FAILED"
    print("Verify invalid source path test - SUCCESS")

    # Invalid destination path test
    cmd = copy + " " + username + " " + hostip + \
        " " + srcpath + " " + invaliddestpath
    out = switch1(cmd)

    assert destfailmsg in out, \
        "Verify invalid destination path test - FAILED"
    print("Verify invalid destination path test - SUCCESS")


@mark.gate
def test_sftp_ft(topology, step):
    ops1 = topology.get("ops1")
    ops2 = topology.get("ops2")

    assert ops1 is not None
    assert ops2 is not None

    step("### SFTP server enable/disable test ###")
    # SFTP server enable test
    sftp_server_config_test(ops2, True)
    # SFTP server disable test
    sftp_server_config_test(ops2, False)

    step("### SFTP client get test ###")
    sftp_client_get(ops1, ops2)

    step("### SFTP client interactive mode test ###")
    sftp_client_int(ops1, ops2)

    step("### SFTP post server disable test ###")
    sftp_post_server_disable(ops1, ops2)

    step("### SFTP negative test cases ###")
    sftp_fail_cases(ops1, ops2)
