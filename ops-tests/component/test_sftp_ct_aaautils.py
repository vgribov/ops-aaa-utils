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
from pytest import mark

TOPOLOGY = """
#
# +-------+
# |  sw1  |
# +-------+
#

# Nodes
[type=openswitch name="Switch 1"] sw1
"""


@mark.gate
def test_sftp_server_feature(topology, step):
    sw1 = topology.get('sw1')

    assert sw1 is not None

    out = sw1('cat /etc/ssh/sshd_config | grep sftp', shell='bash')
    assert "#Subsystem	sftp	/usr/lib/openssh/sftp-server" in out, \
        "SFTP server is not disabled by default"

    sw1('configure terminal')
    # enable the sftp server
    ret = sw1('sftp server enable')
    sw1('end')
    assert ret == '', "Enable SFTP server failed"

    out = sw1('cat /etc/ssh/sshd_config | grep sftp', shell='bash')
    assert "Subsystem\tsftp\t/usr/lib/openssh/sftp-server" in out, \
        "Failed to enable SFTP server in sshd_config file"

    # disable the sftp server
    sw1('configure terminal')
    ret = sw1('no sftp server enable')
    assert ret == '', "Disable SFTP server failed"

    out = sw1('cat /etc/ssh/sshd_config | grep sftp', shell='bash')
    assert "#Subsystem\tsftp\t/usr/lib/openssh/sftp-server" in out, \
        "Failed to disable SFTP server in sshd_config file"
