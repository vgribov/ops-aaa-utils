# SFTP server Feature Test Cases

The following test cases verify AAA configuration :

- [Test Cases](#test-cases)
	- [Verify SFTP server feature](#verify-sftp-server-feature)
		- [Test case 1.01 : Verify SFTP server is disabled during start up](#test-case-1.01-:-verify-sftp-server-is-disabled-during-start-up)
		- [Test case 1.02 : Verify SFTP server enable](#test-case-1.02-:-verify-sftp-server-enable)
		- [Test case 1.03 : Verify SFTP server enable](#test-case-1.03-:-verify-sftp-server-disable)

#Test Cases #
##  Verify SFTP server feature ##
### Objective ###
Verify the SFTP server feature.
### Requirements ###
The requirements for this test case are:
 - Docker version 1.7 or above.
 - Accton AS5712 switch docker instance.

### Setup ###
#### Topology Diagram ####
              +------------------+
              |                  |
              |  AS5712 switch   |
              |                  |
              +------------------+

#### Test Setup ####
AS5712 switch instance.

### Test case 1.01 : Verify SFTP server is disabled during start up ###
### Description ###
Verify the SSHD configuration file and check SFTP server is disabled
### Test Result Criteria ###
#### Test Pass Criteria ####
The SSHD configuration file have the SFTP server disabled.
#### Test Fail Criteria ####
The SSHD configuration file have the SFTP server enabled.

### Test case 1.02 : Verify SFTP server enable ###
### Description ###
When user enables SFTP server through CLI or REST, SSHD configuration file should be modified accordingly.
### Test Result Criteria ###
#### Test Pass Criteria ####
SSHD configuration file modified to enable SFTP server.
#### Test Fail Criteria ####
SSHD configuration file not modified to enable SFTP server.

### Test case 1.03 : Verify SFTP server disable ###
### Description ###
When user enables SFTP server through CLI or REST, SSHD configuration file should be modified accordingly.
### Test Result Criteria ###
#### Test Pass Criteria ####
SSHD configuration file modified to disable SFTP server.
#### Test Fail Criteria ####
SSHD configuration file not modified to disable SFTP server.
