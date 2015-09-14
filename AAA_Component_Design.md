High level design of OPS-AAA-UTILS
============================

The primary goal of the ops-aaa-utils module is to facilitate the user authentication to the switch. This modules core component is aaautilspamcfg daemon. This daemon modifies PAM configuration files, SSH configuration file and RADIUS client file accordingly with the values saved in OVSDB.

Responsibilities
---------------
- The aaautilspamcfg daemon registered to columns and tables of OVSDB which are responsible for this feature, and daemon has a ability to listen to the changes of those columns/tables.
- When the daemon gets a notification of change in the OVSDB, it does the following:
    - Modify respective PAM configuration files "/etc/pam.d/common-*-access" if there is a change in aaa column for RADIUS or fallback key.
    - Modifies SSH configuration file "/etc/ssh/sshd_config" if there is a change in aaa column for pub_key_authentication or password_authetication key.
    - Modifies RADIUS "/etc/raddb/server" client if there is a change in RADIUS table.

Design choices
--------------
The design choices made for ops-aaa-utils modules are:

- The default authentication method is local and fallback to local is enabled.
- By default public key authentication and password authentication is enabled.
- The default value of shared secret used for communication between the switch and RADIUS server is "testing123-1".
- The default value of the port used for communication with RADIUS server is 1812.
- The default value of number of connection retries is 1.
- The default value of connection timeout is 5 seconds.

Relationships to external OpenSwitch entities
--------------------
The following diagram provides detailed description of relationships and interactions of ops-aaa-utils modules with other modules in the switch.

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
               | |      Open_vSwitch       |       |   RADIUS Server  | |
               | |-aaa column              |       |      Table       | |
               | |-radius_server Ref Table-+------>|                  | |
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

For more information on auto provisioning please refer to [Auto Provisioning](http://www.openswitch.net/docs/autoprovisioing)

OVSDB-Schema
------------
The ops-aaa-utils module related columns on OpenvSwitch table are "aaa" column and "radius\_server" column which is reference to "Radius\_Servers" table. Refer vswitchd.xml file for
description and default values of these "aaa" column and  "Radius\_Server" table.

              +-----------------------------------------------------+
              |                     OVSDB                           |
              |   +---------------+                                 |
              |   | Open_vSwitch  |                                 |
              |   |               |                                 |
              |   | - aaa         |         +--------------------+  |
              |   | - radius      |         |     Radius_Server  |  |
              |   |   server -----|-------->|       Table        |  |
              |   +---------------+         +--------------------+  |
              |                                                     |
              +-----------------------------------------------------+
Internal structure
------------------
The various functionality of sub modules are :

####CLI####
The CLI module is used for configuring user authentication, RADIUS server configuration. The CLI provides basic sanity check of the parameters entered like checking the validity of the IP entered, authentication port, retries and timeout ranges.
The "aaa" column and "Radius\_Server" table will be updated by the CLI.

For more information on CLI please refer to [AAA_CLI](http://www.openswitch.net/docs/CLI)
####REST####
REST module works similar to CLI.

References
----------
* [Reference 1](http://www.openswitch.net/docs/redest1)
* ...

TBD: Include references CLI, REST.
