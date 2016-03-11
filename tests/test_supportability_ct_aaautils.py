
# (C) Copyright 2016 Hewlett Packard Enterprise Development LP
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

from opstestfw import testEnviron, LogOutput

topoDict = {"topoExecution": 120,
            "topoDevices": "dut01",
            "topoFilters": "dut01:system-category:switch"}

# Global variables
dut01Obj = None


def checkAAADaemonDiag(dut01Obj, daemon, feature):
    # Variables
    overallBuffer = []
    finalReturnCode = 0
    str_check = 'diag-dump feature for AAA is not implemented'
    vtysh_cmd = 'diag-dump ' + feature + ' basic'
    tc_desc = vtysh_cmd + ' test '

    LogOutput('info', "\n############################################")
    LogOutput('info', "1.1 Running Diagnostic test for AAA. " + tc_desc)
    LogOutput('info', "############################################\n")

    shell_cmd = "cp /etc/openswitch/supportability/ops_featuremapping.yaml\
     /etc/openswitch/supportability/ops_featuremapping.yaml2 "
    returnDevInt = dut01Obj.DeviceInteract(command=shell_cmd)
    LogOutput('info', str(returnDevInt['buffer']))

    shell_cmd = 'printf \'\n  -\n    feature_name: \"' + feature + \
        '\"\n    feature_desc: \"AAA feature Sample\"\n' + \
        '    daemon:\n     - \"' + daemon + '\"    ' + ' \' ' + \
        ' > /etc/openswitch/supportability/ops_featuremapping.yaml'

    dut01Obj.DeviceInteract(command=shell_cmd)
    LogOutput('info', str(returnDevInt['buffer']))

    dut01Obj.VtyshShell(enter=True)
    returnDevInt = dut01Obj.DeviceInteract(command=vtysh_cmd)
    LogOutput('info', str(returnDevInt['buffer']))

    dut01Obj.VtyshShell(enter=False)

    finalReturnCode = returnDevInt['returnCode']
    overallBuffer.append(returnDevInt['buffer'])

    shell_cmd = "mv /etc/openswitch/supportability/ops_featuremapping.yaml2\
     /etc/openswitch/supportability/ops_featuremapping.yaml "
    dut01Obj.DeviceInteract(command=shell_cmd)

    if finalReturnCode != 0:
        LogOutput('error',
                  "Failed to run " + tc_desc +
                  " on device " + str(dut01Obj.device))
        return False
    else:
        if (str_check not in returnDevInt['buffer']):
            LogOutput(
                'error', tc_desc + "Test Case Failure,refer output below")
            for outputs in overallBuffer:
                LogOutput('info', str(outputs))
            return False
        else:
            LogOutput('info',
                      tc_desc + "ran successfully on device " +
                      str(dut01Obj.device))
            return True


class Test_diag_dump:

    def setup_class(cls):
        # Create Topology object and connect to devices
        Test_diag_dump.testObj = testEnviron(
            topoDict=topoDict)
        Test_diag_dump.topoObj = \
            Test_diag_dump.testObj.topoObjGet()
        # Global variables
        global dut01Obj
        dut01Obj = cls.topoObj.deviceObjGet(device="dut01")

    def test_diag_dump_unsupported_daemon(self):
        assert(
            checkAAADaemonDiag(dut01Obj, 'ops_aaautilspamcfg', 'ops-aaa'))

   # Teardown Class
    def teardown_class(cls):
        # Terminate all nodes
        Test_diag_dump.topoObj.terminate_nodes()
