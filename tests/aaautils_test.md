Component Test Cases
============

[toc]

##  Daemon Testing##
### Objective ###
This test is to verify if the daemon is able to get notification of a change in OVSDB and modify the PAM configuration files, the SSH configuration file and the RADIUS client file.
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
### Test case 1.01 : Verify if daemon is running ###
### Description ###
Boot the switch with the image and check if aaautilspamcfg daemon is running or not.

### Test Result Criteria ###
#### Test Pass Criteria ####
`systemctl status aaautils.service`  should be active and running.
#### Test Fail Criteria ####
`systemctl status aaautils.service` is suspended or in active.

### Test case 1.02 : Verify if the PAM configuration files modified to local authentication###
### Description ###
When user configures only local authentication through CLI or REST, all the PAM configuration files should be modified to local authentication.

### Test Result Criteria ###
#### Test Pass Criteria ####
PAM configuration files modified to local authentication.
#### Test Fail Criteria ####
PAM configuration files not modified to local authentication.

### Test case 1.03 : Verify if the PAM configuration files modified to RADIUS authentication ###
### Description ###
When user configures only RADIUS authentication through CLI or REST, all the PAM configuration files should be modified to the RADIUS authentication.

### Test Result Criteria ###
#### Test Pass Criteria ####
The PAM configuration files modified to RADIUS authentication.
#### Test Fail Criteria ####
The PAM configuration files not modified to RADIUS authentication.

### Test case 1.04 : Verify if the PAM configuration files modified to RADIUS authentication and fallback to local###
### Description ###
When user configures only RADIUS authentication and fallback to local authentication through CLI or REST, all the PAM configuration files should be modified accordingly.

### Test Result Criteria ###
#### Test Pass Criteria ####
The PAM configuration files modified to RADIUS authentication and fallback to local authentication.
#### Test Fail Criteria ####
The PAM configuration files not modified to RADIUS authentication and fallback to local authentication.

### Test case 1.05 : Verify if the SSH configuration file is modified to public key authentication###
### Description ###
When user configures SSH authentication method to public key authentication through CLI or REST, SSH configuration file should be modified accordingly.

### Test Result Criteria ###
#### Test Pass Criteria ####
The SSH configuration file modified to public key authentication enable.
#### Test Fail Criteria ####
The SSH configuration file not modified to public key authentication enable.

### Test case 1.06 : Verify if the SSH configuration file is modified to password authentication###
### Description ###
When user configures SSH authentication method to password authentication through CLI or REST, SSH configuration file should be modified accordingly.

### Test Result Criteria ###
#### Test Pass Criteria ####
SSH configuration file modified to password authentication enable.
#### Test Fail Criteria ####
SSH configuration file not modified to password authentication enable.

### Test case 1.07 : Verify if RADIUS server information is saved in the RADIUS client file###
### Description ###
When user configures one RADIUS server, then the RADIUS client file is updated accordingly with IP address and other default values.

### Test Result Criteria ###
#### Test Pass Criteria ####
RADIUS server IP and default shared secret, authentication port, retries and timeout are configured in the RADIUS client file.
#### Test Fail Criteria ####
RADIUS client file is not modified.

### Test case 1.08 : Verify if RADIUS server shared secret is modified in the RADIUS client file###
### Description ###
When user configures shared secret for one RADIUS server, RADIUS client file is updated accordingly with new shared secret.

### Test Result Criteria ###
#### Test Pass Criteria ####
New shared secret is updated in the RADIUS client file for that configured RADIUS server.
#### Test Fail Criteria ####
New shared secret is not updated in the RADIUS client file.

### Test case 1.09 : Verify if RADIUS server authentication port is modified in the RADIUS client file###
### Description ###
When user configures authentication port number for one RADIUS server, RADIUS client file is updated accordingly with new authentication port.

### Test Result Criteria ###
#### Test Pass Criteria ####
New authentication port is updated in the RADIUS client file for that configured RADIUS server.
#### Test Fail Criteria ####
New authentication port is not updated in the RADIUS client file.

### Test case 1.10 : Verify if RADIUS server retries is modified in the RADIUS client file###
### Description ###
When user configures RADIUS server retires, RADIUS client file is updated accordingly with new retries value.

### Test Result Criteria ###
#### Test Pass Criteria ####
New retries value is updated in the RADIUS client file for all RADIUS server.
#### Test Fail Criteria ####
New retries value is not updated in the RADIUS client file.

### Test case 1.11 : Verify if RADIUS server timeout is modified in the RADIUS client file###
### Description ###
When user configures RADIUS server timeout, RADIUS client file is updated accordingly with new retries value.

### Test Result Criteria ###
#### Test Pass Criteria ####
New timeout value is updated in the RADIUS client file for all RADIUS server.
#### Test Fail Criteria ####
New timeout value is not updated in the RADIUS client file.

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
### Test case 2.01 : Verify if new users with password can be added from vtysh###
### Description ###
Boot the switch with the latest image and user has privilege to add new users with password.

### Test Result Criteria ###
#### Test Pass Criteria ####
New user is ablee to log in and vtysh shell is prompted.
#### Test Fail Criteria ####
New user is not able to login.

### Test case 2.02 : Verify if users password can be modified from vtysh###
### Description ###
Boot the switch with the latest image and user has privilege to modify password of existing user except root.

### Test Result Criteria ###
#### Test Pass Criteria ####
Existing user is able to log in with new password and vtysh shell is prompted.
#### Test Fail Criteria ####
Existing user is not able to log in with new password.

### Test case 2.03 : Verify if existing users can be deleted from vtysh###
### Description ###
Boot the switch with the latest image and user has privilege to delete existing users, except root and current logged in user.

### Test Result Criteria ###
#### Test Pass Criteria ####
Deleted user cannot be logged in further.
#### Test Fail Criteria ####
Deleted user able to login.

### Test case 2.04 : Verify if un supported username can be added from vtysh###
### Description ###
Boot the switch with the latest image and try adding a new user with invalid format.

### Test Result Criteria ###
#### Test Pass Criteria ####
Current logged in user is not able to add a new user with invalid format.
#### Test Fail Criteria ####
Current logged in user is able to add a new user with invalid format.

Refrence:
---------
For more information refer to design document [DESIGN](https://openswitch.net/ops-aaa-utils/docs/DESIGN.md)
For more information refer to cli document [CLI](https://openswitch.net/docs/AAA_cli.md)
