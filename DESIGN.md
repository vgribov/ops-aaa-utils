High-level design of OPS-AAA-UTILS
============================

The primary goal of the `ops-aaa-utils` module is to facilitate the user authentication to the switch. This modules core component is the `ops-aaautilspamcfg` daemon. This daemon modifies the PAM configuration files, the SSH configuration file and the RADIUS client file accordingly with the values saved in OVSDB.


Responsibilities
---------------
- The `ops-aaautilspamcfg` daemon registered to OVSDB columns and tables. The OVSDB columns and tbles are responsible for this feature, and the daemon has the ability to listen to the changes of those columns and tables.
- When the daemon gets a change notification in the OVSDB, it performs the following tasks:
	- Modifies the PAM configuration files `/etc/pam.d/common-*-access` if there is a change in the `aaa` column for RADIUS or fallback key.
	- Modifies the SSH configuration file `/etc/ssh/sshd_config` if there is a change in the `aaa` column for `pub_key_authentication` or `password_authetication` key.
	- Modifies the RADIUS client file `/etc/raddb/server`  if there is a change in RADIUS table.

Design choices
--------------
The design choices made for `ops-aaa-utils` modules are:
- The default authentication method is local and fallback to local is enabled.
- By default public key authentication and password authentication is enabled.
- The default shared secret used for communication between the switch and teh RADIUS server is `testing123-1`.
- The default port number used for communication with the RADIUS server is `1812`.
- The default number of connection retries is `1`.
- The default connection timeout is `5` seconds.

Relationships to external OpenSwitch entities
--------------------
The following diagram provides detailed description of relationships and interactions of `ops-aaa-utils` modules with other modules in the switch.

               +--------------------+             +--------------------+
               |                    |             |                    |
               |                    |             |                    |
               |    CLI             |             |       REST         |
               |                    |             |                    |
               +---------+----------+             +---------+----------+
                         |                                  |
                         |                                  |
                         |                                  |
               +---------v----------------------------------v-----------+
               |                      OVSDB                             |
               | +-------------------------+       +------------------+ |
               | |      System             |       |   RADIUS Server  | |
               | |-aaa column              |       |      Table       | |
               | |-radius_servers Ref Table+------>|                  | |
               | +-------------------------+       +------------------+ |
               +-+-------------------+----------------------------------+
                 |                   |
                 |                   |
                 |                   |                      +---------------------------+
      +----------v-+    +------------v--------------+       | PAM Configuration Files   |
      |            |    |                           +------>+---------------------------+
      |    Auto    |    |  AAA Daemon               |       +---------------------------+
      |Provisioning|    |                           +------>| SSH Configuration File    |
      |            |    |                           |       +---------------------------+
      +------------+    +---------------------------+------>+---------------------------+
                                                            | RADIUS Client             |
                                                            +---------------------------+

For more information on auto provisioning please refer to [Auto Provisioning](/documents/user/autoprovision_user_guide)

OVSDB-Schema
------------
The `ops-aaa-utils` module related columns on `System` table are `aaa` column and `radius_servers` column which is a reference to `Radius_Server` table. Refer `vswitchd.xml` file for
description and default values of these `aaa` column and  `Radius_Server` table.

              +-----------------------------------------------------+
              |                     OVSDB                           |
              |   +---------------+                                 |
              |   | Open_vSwitch  |                                 |
              |   |               |                                 |
              |   | - aaa         |         +--------------------+  |
              |   | - radius      |         |     Radius_Server  |  |
              |   |   servers ----|-------->|       Table        |  |
              |   +---------------+         +--------------------+  |
              |                                                     |
              +-----------------------------------------------------+
Internal structure
------------------
The various functionality of sub modules are :

####CLI####
The CLI module is used for configuring user authentication and the RADIUS server configuration. The CLI provides basic sanity check of the parameters entered like:
- Checking the validity of the IP entered.
- The authentication port number range.
- The connection retries range.
- The connection timeout range.
The `aaa` column and `Radius_Server` table will be updated by the CLI.

####REST####
REST module works similar to CLI.

# High level design of autoprovisioning

## Feature description
Autoprovisioning is implemented by adding hooks to the DHCP client. Openswitch uses the dhclient package which allows the users to add entry and exit hooks.

## Responsibilities
* Process incoming DHCP replies and extract option 239
* Execute autoprovisioning procedure and update the status in OVSDB

## Design choices
The design was selected to avoid making any code changes to dhclient and to extend the functionality by mechanisms supported by dhclient.

## Relationships to external OpenSwitch entities
External OpenSwitch entities interact with the OVSDB and the dhclient package.

## OVSDB-Schema
Column **auto\_provisioning_status** resides in the System table amd is used to store the status of autoprovision.

## Internal structure
The internal structure is implemented using python. The file autoprovision.py is called by the dhclient exit hook amd passes the value of option 239 (URL of provisioning script on server) as an argument. The code performs the following actions:

- Connects to OVSDB and builds the idl object
- Fetches the provisioning script from the specified URL
- Executes the script
- Updates the autoprovision status to the OVSDB table System, column auto_provisioning_status.

## References
For the AAA Command Reference document, refer to [CLI](/documents/user/AAA_cli)
For the Autoprovision Command Reference document, refer to [Autoprovision Command Reference](/documents/user/autoprovision_CLI)
