#!/usr/bin/env python
# Copyright (C) 2015 Hewlett Packard Enterprise Development LP
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from smart import Error, _
from smart.util import pexpect

import os
import sys
from time import sleep
import pytest

from opsvsi.docker import *
from opsvsi.opsvsitest import *

HTTP_SERVER = "http://127.0.0.1/autoprovision"
HTTP_SERVER_ROOT_PATH = "/var/www/servers/www.example.org/pages/"
SCRIPT_NAME = "autoprovision"
TEST_ECHO_STRING = "Hello from Autoprovision script"
LIGHTTPD_CONFIG = "./src/ops-aaa-utils/tests/lighttpd.conf"


class autoprovisionFeatureTest(OpsVsiTest):
    def setupHttpServer(self):
        ''' This function is to setup http server in the ubuntu image
        we are referring to
        '''
        s1 = self.net.switches[0]

        #Configure lighttpd conf file and root path of server
        s1.cmd("mkdir -p " + HTTP_SERVER_ROOT_PATH)
        with open(LIGHTTPD_CONFIG) as f_config:
            config = f_config.read()

        s1.cmd(config)

        s1.cmd("killall -9 lighttpd")
        sleep(1)
        out = s1.cmd("lighttpd -t -f ~/lighttpd.conf")
        out += s1.cmd("echo ")

        if "Syntax OK" in out:
            out = s1.cmd("lighttpd -f ~/lighttpd.conf")
        else:
            assert ("Syntax OK" in out), "Failed to setup lighttpd server"

        return True

    def setupAutoprovisionScript(self):
        ''' This function is to setup autoprovision script in http server
        '''
        s1 = self.net.switches[0]
        out = s1.cmd("touch " + HTTP_SERVER_ROOT_PATH + SCRIPT_NAME)

        s1.cmd("echo \'#!/bin/sh\' >>" + HTTP_SERVER_ROOT_PATH + SCRIPT_NAME)
        s1.cmd("echo \'#OPS-PROVISIONING\'>>" + HTTP_SERVER_ROOT_PATH +
               SCRIPT_NAME)
        s1.cmd("echo echo "+TEST_ECHO_STRING+" >>" + HTTP_SERVER_ROOT_PATH +
               SCRIPT_NAME)

        return True

    def setupNet(self):
        # Create a topology with single openswitch
        self.net = Mininet(topo=SingleSwitchTopo(k=1, hopts=self.getHostOpts(),
                           sopts=self.getSwitchOpts()),
                           switch=VsiOpenSwitch,
                           host=OpsVsiHost,
                           link=OpsVsiLink, controller=None,
                           build=True)

        if self.setupHttpServer():
            info('*** setupHttpServer success\n')

        if self.setupAutoprovisionScript():
            info('*** setupAutoprovisionScript success\n')

    def executeAutoprovision(self):
        ''' This function download autoprovision script from http server
        and execute it
        '''
        info('\n########## Executing Autoprovision ##########\n')
        s1 = self.net.switches[0]
        out = s1.cmd("autoprovision "+HTTP_SERVER)
        out += s1.cmdCLI("end")

        if not TEST_ECHO_STRING in out:
            assert (TEST_ECHO_STRING in out), \
                "Failed in executing autoprovision script"
        else:
            info("### Passed:Executing downloaded autoprovision script ###\n")

        out = s1.cmdCLI("show autoprovision")
        out += s1.cmdCLI("end")

        if not HTTP_SERVER in out:
            assert (HTTP_SERVER in out), \
                "Failed in updating autoprovision \
                                        status in DB"
        else:
            info("### Passed: Verify autoprovision status updated in DB ###\n")

        info('\n### Executing Autoprovision again, it should not perform '
             '###\n')
        out = s1.cmd("autoprovision "+HTTP_SERVER)
        out += s1.cmdCLI("end")

        if not "Autoprovisioning already completed" in out:
            assert ("Autoprovisioning already completed" in out),\
                "Failed in executing autoprovision script again"
        else:
            info("### Passed:Executing autoprovision script again,"
                 "autoprovision not performed  ###\n")

@pytest.mark.skipif(True, reason="Skipping since this is failing, need to be rewritten")
class Test_autoprovisionfeature:
    def setup(self):
        pass

    def teardown(self):
        pass

    def setup_class(cls):
        Test_autoprovisionfeature.test = autoprovisionFeatureTest()
        pass

    def teardown_class(cls):
    # Stop the Docker containers, and
    # mininet topology
        Test_autoprovisionfeature.test.net.stop()

    def setup_method(self, method):
        pass

    def teardown_method(self, method):
        pass

    def __del__(self):
        del self.test

    def test_executeAutoprovisionself(self):
        self.test.executeAutoprovision()
