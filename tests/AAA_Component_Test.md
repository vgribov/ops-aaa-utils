<!--  See the https://github.com/adam-p/markdown-here/wiki/Markdown-Cheatsheet for additional information about markdown text.
Here are a few suggestions in regards to style and grammar:
* Use active voice. With active voice, the subject is the doer of the action. Tell the reader what
to do by using the imperative mood, for example, Press Enter to view the next screen. See https://en.wikipedia.org/wiki/Active_voice for more information about the active voice.
* Use present tense. See https://en.wikipedia.org/wiki/Present_tense for more information about using the present tense.
* The subject is the test case. Explain the actions as if the "test case" is doing them. For example, "Test case configures the IPv4 address on one of the switch interfaces". Avoid the use of first (I) or second person. Explain the instructions in context of the test case doing them.
* See https://en.wikipedia.org/wiki/Wikipedia%3aManual_of_Style for an online style guide.
 -->
Component Test Cases
============

<!--Provide the name of the grouping of commands, for example, LLDP commands-->

1. Daemon testing.
2. User configuration testing.

##  1. Daemon Testing##
### Objective ###
This test is to verify if daemon is able to get notification of a change in OVSDB and modify pam configuration files, ssh configuration file and RADIUS client file.
### Requirements ###
The requirements for this test case are:

 - Latest openswitch image with physical Accton AS5712 switch or
 - Latest openswitch VSI image
### Setup ###
#### Topology Diagram ####

           AS5712 Switch
         +---------------------------------------------------+
         |                             +---------------+     |
         |                             |               |     |
         |                             |
         |                             |   OVSDB       |     |
         |                             |               |     |
         |                             |               |     |
         | +---------------------+     |               |     |
         | |aaa-utils Daemon     |<----|               |     |
         | +---------------------+     +---------------+     |
         +---------------------------------------------------+
#### Test Setup ####
### Test case 1.01 : Test to verify if daemon is running###
### Description ###
Boot the switch with the image and check if aaautilspamcfg daemon is running or not.

### Test Result Criteria ###

#### Test Pass Criteria ####
systemctl status aaautils.service  should be active and running.
#### Test Fail Criteria ####
systemctl status aaautils.service is suspended or in active.

### Test case 1.02 : Test to verify if PAM configuration files modified to local authentication###
### Description ###
When user configures only local authentication through CLI or REST, all PAM configuration files should be modified to local authentication.
### Test Result Criteria ###
#### Test Pass Criteria ####
PAM configuration files modified to local authentication.
#### Test Fail Criteria ####
PAM configuration files not modified to local authentication.

### Test case 1.03 : Test to verify if PAM configuration files modified to RADIUS authentication###
### Description ###
When user configures only RADIUS authentication through CLI or REST, all PAM configuration files should be modified to RADIUS authentication.
### Test Result Criteria ###

#### Test Pass Criteria ####
PAM configuration files modified to RADIUS authentication.
#### Test Fail Criteria ####
PAM configuration files not modified to RADIUS authentication.

### Test case 1.04 : Test to verify if PAM configuration files modified to RADIUS authentication and fallback to local###
### Description ###
When user configures only RADIUS authentication and fallback to local authentication through CLI or REST, all PAM configuration files should be modified accordingly.
### Test Result Criteria ###

#### Test Pass Criteria ####
PAM configuration files modified to RADIUS authentication and fallback to local authentication.
#### Test Fail Criteria ####
PAM configuration files not modified to RADIUS authentication and fallback to local authentication.

### Test case 1.05 : Test to verify if SSH configuration file modified to public key authentication###
### Description ###
When user configures SSH authentication method to public key authentication through CLI or REST, SSH configuration file should be modified accordingly.
### Test Result Criteria ###
#### Test Pass Criteria ####
SSH configuration file modified to public key authentication enable.
#### Test Fail Criteria ####
SSH configuration file not modified to public key authentication enable.

### Test case 1.06 : Test to verify if SSH configuration file modified to password authentication###
### Description ###
When user configures SSH authentication method to password authentication through CLI or REST, SSH configuration file should be modified accordingly.
### Test Result Criteria ###

#### Test Pass Criteria ####
SSH configuration file modified to password authentication enable.
#### Test Fail Criteria ####
SSH configuration file not modified to password authentication enable.

### Test case 1.07 : Test to verify if RADIUS server information is saved in RADIUS client file###
### Description ###
When user configures one RADIUS server, RADIUS client file is updated accordingly with IP address and other default values.
### Test Result Criteria ###

#### Test Pass Criteria ####
RADIUS server IP and default shared secret, authentication port, retries and timeout are configured in RADIUS client file.
#### Test Fail Criteria ####
RADIUS client file is not modified.

### Test case 1.08 : Test to verify if RADIUS server shared secret is modified in RADIUS client file###
### Description ###
When user configures shared secret for one RADIUS server, RADIUS client file is updated accordingly with new shared secret.
### Test Result Criteria ###

#### Test Pass Criteria ####
New shared secret is updated to RADIUS client file for that particular RADIUS server.
#### Test Fail Criteria ####
New shared secret is not updated to RADIUS client file.

### Test case 1.09 : Test to verify if RADIUS server authentication port is modified in RADIUS client file###
### Description ###
When user configures authentication port number for one RADIUS server, RADIUS client file is updated accordingly with new authentication port.
### Test Result Criteria ###

#### Test Pass Criteria ####
New authentication port is updated to RADIUS client file for that particular RADIUS server.
#### Test Fail Criteria ####
New authentication port is not updated to RADIUS client file.

### Test case 1.10 : Test to verify if RADIUS server retries is modified in RADIUS client file###
### Description ###
When user configures RADIUS server retires, RADIUS client file is updated accordingly with new retries value.
### Test Result Criteria ###

#### Test Pass Criteria ####
New retries value is updated to RADIUS client file for all RADIUS server.
#### Test Fail Criteria ####
New retries value is not updated to RADIUS client file.

### Test case 1.11 : Test to verify if RADIUS server timeout is modified in RADIUS client file###
### Description ###
When user configures RADIUS server timeout, RADIUS client file is updated accordingly with new retries value.
### Test Result Criteria ###

#### Test Pass Criteria ####
New timeout value is updated to RADIUS client file for all RADIUS server.
#### Test Fail Criteria ####
New timeout value is not updated to RADIUS client file.

##  2. User configuration testing.##
### Objective ###
This test is to verify whether new users are added, password for existing user has been modified and deleting existing users.
### Requirements ###
The requirements for this test case are:

 - Latest openswitch image with physical Accton AS5712 switch or
 - Latest openswitch VSI image
### Setup ###
#### Topology Diagram ####
              +------------------+
              |                  |
              |  AS5712 switch   |
              |                  |
              +------------------+

#### Test Setup ####
### Test case 2.01 : Test to verify if new users with password can be added from vtysh###
### Description ###
Boot the switch with the image and user has privilege to add new users with password.

### Test Result Criteria ###

#### Test Pass Criteria ####
New user logged in and prompted vtysh shell.
#### Test Fail Criteria ####
New user not able to login, and vtysh shell is not prompted

### Test case 2.02 : Test to verify if users password can be modified from vtysh###
### Description ###
Boot the switch with the mentioned image and user has privilege to modify password of existing user except root.

### Test Result Criteria ###

#### Test Pass Criteria ####
User logged in with existing user and new password. vtysh shell is prompted after successful login.
#### Test Fail Criteria ####
User not able to login with new password, and vtysh shell is not prompted

### Test case 2.03 : Test to verify if existing users can be deleted from vtysh###
### Description ###
Boot the switch with the mentioned image and user has privilege to delete existing users, except root and current logged in user.

### Test Result Criteria ###

#### Test Pass Criteria ####
Deleted user cannot be logged in further.
#### Test Fail Criteria ####
Deleted user able to login.

Refrence:
---------
Refer to this link for more information on CLI - TBD [here](https://openswitch.net/cli_feature_name.html#cli_command_anchor)
