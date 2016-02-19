#CHAP Component Test Cases
##Testcases
[TOC]

##Testcase 1: Basic Configuration
*Objective:* Verify if the switch can save the basic configuration of CHAP and PAP.
*Requirements:*
* Physical or Virtual Switch

*Setup:*
* Topology Diagram:

              +------------------+
              |                  |
              |  AS5712 switch   |
              |                  |
              +------------------+

*Description:*
Enable CHAP or PAP authentication and verify if the switch save the configuration.

* Steps:

1. Enable PAP Authentication.
2. Save configuration.
3. Check configuration and verify the authentication method.
4. Change to CHAP Authentication.
5. Save configuration.
6. Check configuration and verified the authentication method.

*Test result criteria*

* Test pass criteria

1. The switch saves the configuration for PAP and displayed the configuration.
2. The switch saves the configuration for CHAP and displayed the configuration.

* Test fail criteria
1. The switch does not save the configuration for PAP.
2. The switch does not save the configuration for CHAP.

##Testcase 2: Delete Configuration
*Objective:* Verify if the configuration of CHAP and PAP is removed on the Switch.
*Requirements:*
* Physical or Virtual Switch

*Setup:*
* Topology Diagram:

              +------------------+
              |                  |
              |  AS5712 switch   |
              |                  |
              +------------------+

*Description*
Enable CHAP or PAP authentication and verify if the switch delete the configuration.

*Steps:

1. Enable PAP Authentication.
2. Save configuration.
3. Check configuration and verify the authentication method.
4. Delete the configuration of switch.
5. Check configuration and verify if the PAP authentication method was removed.
6. Enable CHAP Authentication.
7. Save configuration.
8. Check configuration and verify the authentication method.
9. Delete the configuration of CHAP.
10. Check configuration and verify the CHAP authentication method was removed.

*Test result criteria*
* Test pass criteria

1. The switch deletes the configuration for PAP.
2. The switch deletes the configuration for CHAP.

* Test fail criteria

1. The switch does not delete the configuration for PAP.
2. The switch does not delete the configuration for CHAP.

##Testcase 3: Wrong Configuration
*Objective:* Verify if the switch can allow other options instead of PAP or CHAP.
*Requirements:*
* Physical or Virtual Switch

*Setup:*
* Topology Diagram:
              +------------------+
              |                  |
              |  AS5712 switch   |
              |                  |
              +------------------+

*Description:*
Attempt to configure another option instead of PAP or CHAP

* Steps:

1. Attempt to enable other option using the command.
2. Verify that the switch displays an error message.

*Test result criteria*
* Test pass criteria

1. The switch does not allow other option instead of PAP or CHAP.
2. The  switch displays an error message

* Test fail criteria

1. The switch allows other option instead of PAP or CHAP.
2. The  switch does not display an error message

##Testcase 4: Save Configuration and Reboot the Switch
*Objective:* Verify if the switch keeps the configuration after reboot.
*Requirements:*
* Physical or Virtual Switch

*Setup:*
* Topology Diagram:

              +------------------+
              |                  |
              |  AS5712 switch   |
              |                  |
              +------------------+

*Description:*
Enable CHAP or PAP authentication and verify if the switch keeps the configuration.

* Steps:

1. Enable PAP Authentication.
2. Save configuration.
3. Check configuration and verified the authentication method.
4. Reboot the Switch.
5. Check configuration and verified the authentication method.
6. Change to CHAP Authentication.
7. Save configuration.
8. Check configuration and verified the authentication method.
9. Reboot the Switch.
10. Check configuration and verified the authentication method.

*Test result criteria*
* Test pass criteria

1. The switch keeps PAP authentication after the reboot.
2. The switch keeps CHAP authentication after the reboot.

* Test fail criteria

1. The switch does not keep PAP authentication after the reboot.
2. The switch does not keep CHAP authentication after the reboot.

##Testcase 5: User Authentication
*Objective:* Verify if a user can be authenticated by the Radius Server if CHAP is enable.
*Requirements:*
* Physical or Virtual Switch
* Radius Server

*Setup:*
* Topology Diagram:

         +------------------+          +------------+
         |                  |          |            |
         |  AS5712 switch   |----------|   RADIUS   |
         |                  |          |            |
         +------------------+          +------------+

*Description:*
Enable CHAP authentication and verify if a user can be authenticated.

* Steps:

1. Configure an IP Address on the Interface of the Radius Server
2. Configure an IP Address on the Interfaces of the Switch
3. Enable the interface of the Switch.
4. Verify connection between all devices
5. Configure RADIUS Server to use CHAP Authentication
6. Add the admin user on the Radius Server.
8. Enable AAA authentication using CHAP Method on switch.
9. Configure the Radius Server Host on the Switch.
10. Verify the configuration on the Switch.
11. Login to the switch with the admin user.
12. Verify on the logs of the Radius Server that the user was authenticated.

*Test result criteria*
* Test pass criteria

1. The user is authenticated using CHAP authentication.

* Test fail criteria

1. The user is not authenticated using CHAP authentication


##Testcase 6: User Authentication with wrong configuration
*Objective:* Verify if a user can’t be authenticated with a wrong configuration on the Switch.
*Requirements:*
* Physical or Virtual Switch
* Radius Server

*Setup:*
* Topology Diagram:

         +------------------+          +------------+
         |                  |          |            |
         |  AS5712 switch   |----------|   RADIUS   |
         |                  |          |            |
         +------------------+          +------------+

*Description:*
Attempt to authenticate a user with a wrong configuration on switch.

* Steps:

1. Configure an IP Address on the Interface of the Radius Server
2. Configure an IP Address on the Interfaces of the Switch
3. Enable the interfaces of the Switch.
4. Verify connection between all devices
5. Configure RADIUS Server to use CHAP Authentication
6. Attempt to login to the switch with the admin user.

*Test result criteria*
* Test pass criteria

1. The user is not authenticated.

* Test fail criteria

1. The user is authenticated.

##Testcase 7: Admin and netop Authentication
*Objective:* Verify if admin and netop users can be authenticated by the Radius Server if CHAP is enable.
*Requirements:*
* Physical or Virtual Switch
* Radius Server

*Setup:*
* Topology Diagram:

         +------------------+          +------------+
         |                  |          |            |
         |  AS5712 switch   |----------|   RADIUS   |
         |                  |          |            |
         +------------------+          +------------+

*Description:*
Enable CHAP authentication and verify if the users: admin and netop can be authenticated.

* Steps:

1. Configure an IP Address on the Interface of the Radius Server
2. Configure an IP Address on the Interfaces of the Switch
3. Enable the interfaces of the Switch.
4. Verify connection between all devices
5. Configure RADIUS Server to use CHAP Authentication
6. Add admin and netop users on the Radius Server
7. Enable AAA authentication using CHAP Method.
8. Configure the Radius Server Host on the Switch.
9. Verify the configuration on the Switch.
10. Login to the switch with the admin user.
11. Login to the switch with the netop user.
12. Verify on the logs of the WS that the users were authenticated.

* Test pass criteria

1. The user admin is authenticated using CHAP authentication.
2. The user netop is authenticated using CHAP authentication.

* Test fail criteria

1. The user admin is not authenticated using CHAP authentication.
2. The user netop is not authenticated using CHAP authentication..

##Testcase 8: Wrong configuration on the Server
*Objective:* Verify if user can’t be authenticated by the Radius Server with wrong configuration.
*Requirements:*
* Physical or Virtual Switch
* Radius Server

*Setup:*
* Topology Diagram:
         +------------------+          +------------+
         |                  |          |            |
         |  AS5712 switch   |----------|   RADIUS   |
         |                  |          |            |
         +------------------+          +------------+
*Description:*
Attempt to authenticate a user with a wrong configuration on radius server.

* Steps:*

1. Configure an IP Address on the Interface of the Radius Server 1
2. Configure an IP Address on the Interfaces of the Switch.
3. Enable the interfaces of the Switch.
4. Verify connection between all devices
5. Configure RADIUS Server to use another authentication method instead CHAP
6. Add admin user on the Radius Server
7. Enable AAA authentication using CHAP Method.
8. Configure the Radius Server Host on the Switch.
9. Attempt to authenticate the user through the WS
10. The user can’t be authenticated.

*Test result criteria*
* Test pass criteria

1. The user is not authenticated.

* Test fail criteria

1. The user is authenticated.

##Testcase 9: Supported Platform
*Objective:* Verify if the CHAP option if only displayed on supported devices.
*Requirements:*
* Physical or Virtual Switch

*Setup:*
* Topology Diagram:

              +------------------+
              |                  |
              |  AS5712 switch   |
              |                  |
              +------------------+

*Description:*
Validate if the CHAP option is displayed on supported devices.

* Steps:

1. Check the platform of the device
2. Verify if the platform supports the CHAP option
3. Attempt to enable AAA authentication using CHAP Method.
4. Verify if the CHAP was enabled or not, according to step 2.


*Test result criteria*
* Test pass criteria

1. The option is enabled on a supported platform.
2. The option is not enabled on a not-supported platform.

* Test fail criteria

1. The option is not enabled on a supported platform.
2. The option is enabled on a not-supported platform.

 ##Testcase 10: Verify CHAP file
*Objective:* Verify if the CHAP file is located in the appropriate location.
*Requirements:*
* Physical or Virtual Switch

*Setup:*
* Topology Diagram:

              +------------------+
              |                  |
              |  AS5712 switch   |
              |                  |
              +------------------+

*Description:*
Validate if the CHAP file is located in the appropriate location.

* Steps:

1. Verify if the file pam_radius_chap_auth.so is located in the appropriate location. (/lib/security)

*Test result criteria*
* Test pass criteria
1. The file pam_radius_chap_auth.so is located in the appropriate location. (/lib/security)

* Test fail criteria
1. The file pam_radius_chap_auth.so is not located in the appropriate location. (/lib/security).
