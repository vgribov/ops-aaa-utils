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

import pytest
import re
from opstestfw import *
from opstestfw.switch.CLI import *
from opstestfw.switch import *

# Topology definition
topoDict = {"topoExecution": 1000,
            "topoTarget": "dut01",
            "topoDevices": "dut01",
            "topoFilters": "dut01:system-category:switch"}


def enterConfigShell(dut01):
    retStruct = dut01.VtyshShell(enter=True)
    retCode = retStruct.returnCode()
    assert retCode == 0, "Failed to enter vtysh prompt"

    return True


def sftpserverfeature(dut01):
    sftpserver_enable = True
    SSHD_CONFIG = "/etc/ssh/sshd_config"

    devIntReturn = dut01.DeviceInteract(command="start-shell")
    retCode = devIntReturn.get('returnCode')
    assert retCode == 0, "Failed to enter bash shell"

    out = dut01.DeviceInteract(command="cat /etc/ssh/sshd_config | grep sftp")

    if "#Subsystem	sftp	/usr/lib/openssh/sftp-server" in out.get('buffer'):
        sftpserver_enable = False

    assert sftpserver_enable is False, "SFTP server is not disabled by default"

    dut01.DeviceInteract(command="exit")

    #enable the sftp server
    dut01.DeviceInteract(command="configure terminal")
    devIntReturn = dut01.DeviceInteract(command="sftp server enable")
    retCode = devIntReturn.get('returnCode')
    assert retCode == 0, "Enable SFTP server failed"
    dut01.DeviceInteract(command="exit")

    devIntReturn = dut01.DeviceInteract(command="start-shell")
    retCode = devIntReturn.get('returnCode')
    assert retCode == 0, "Failed to enter bash shell"

    out = dut01.DeviceInteract(command="cat /etc/ssh/sshd_config | grep sftp")

    if "Subsystem	sftp	/usr/lib/openssh/sftp-server" in out.get('buffer'):
        sftpserver_enable = True

    assert sftpserver_enable is True, "Failed to enable SFTP server in " \
                                      "sshd_config file"

    dut01.DeviceInteract(command="exit")

    #disable the sftp server
    dut01.DeviceInteract(command="configure terminal")
    devIntReturn = dut01.DeviceInteract(command="no sftp server enable")
    retCode = devIntReturn.get('returnCode')
    assert retCode == 0, "Disable SFTP server failed"
    dut01.DeviceInteract(command="exit")

    devIntReturn = dut01.DeviceInteract(command="start-shell")
    retCode = devIntReturn.get('returnCode')
    assert retCode == 0, "Failed to enter bash shell"

    out = dut01.DeviceInteract(command="cat /etc/ssh/sshd_config | grep sftp")

    if "#Subsystem	sftp	/usr/lib/openssh/sftp-server" in out.get('buffer'):
        sftpserver_enable = False

    assert sftpserver_enable is False, "Failed to disable SFTP server " \
                                       "in sshd_config file"
    dut01.DeviceInteract(command="exit")

    return True


class Test_sftpserver_feature:
    def setup_class(cls):
        # Test object will parse command line and formulate the env
        Test_sftpserver_feature.testObj =\
            testEnviron(topoDict=topoDict, defSwitchContext="vtyShell")
        #    Get topology object
        Test_sftpserver_feature.topoObj = \
            Test_sftpserver_feature.testObj.topoObjGet()

    def teardown_class(cls):
        Test_sftpserver_feature.topoObj.terminate_nodes()

    def test_feature(self):
        dut01Obj = self.topoObj.deviceObjGet(device="dut01")
        retValue = sftpserverfeature(dut01Obj)
        if(retValue):
            LogOutput('info', "SFTP server feature - passed")
        else:
            LogOutput('error', "SFTP server feature - failed")
