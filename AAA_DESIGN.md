# AAA Design

## Contents

1. [Overview][1]
2. [Design drivers][2]
3. [Participating modules][3]
4. [Solution][4]
5. [OVSDB-Schema][5]
6. [Design details][6]
7. [Design choices][7]
9. [Standard Reference][9]
10. [References][10]

## Overview
Authentication, authorization, and accounting (AAA) network security services provide a framework
to provide access control on the switch.

AAA is designed to enable a network operator to dynamically configure the authentication,
authorization and accounting mechanisms which define how a user is authenticated during login and
what permissions are allowed for a user after login.

AAA security provides the following services:
- Authentication: This service identifies users, validates the user credentials and allows him to
access the switch.
- Authorization: This service fetches the privileges allowed for the user and describes what the
user is allowed to perform on the switch.
- Accounting: This service provides mechanism to collect information and logs to AAA server for
auditing and reporting purposes.

AAA Server Groups allow grouping of TACACS+ or RADIUS servers as a group so that its easy to
provide groups as primary/secondary mechanisms when using it with
authentication/authorization/accounting services.

Protocols used to provide AAA services:
1. TACACS+ (Terminal Access Controller Access-Control System Plus)
  TACACS+ is used most commonly for administrator access to network devices like routers and
  switches. TACACS+ helps perform Authentication, Authorization and Accounting. TACACS+ separates out
  the authorization functionality, so it enables additional flexibility and granular access controls
  on who can run which commands on specified devices. Each command entered by a user is sent back to
  the central TACACS+ server for authorization, which then checks the command against an authorized
  list of commands for each user or group. TACACS+ can define policies based on user, device type,
  location, or time of day.
2. RADIUS (Remote Authentication Dial-In User Service)
  RADIUS is designed to authenticate and log dial-up remote users to a network. As defined in RFC
  [2865](https://tools.ietf.org/html/rfc2865). RADIUS is a protocol for carrying authentication,
  authorization, and configuration information between an Authenticator which desires to authenticate
  its links and a shared Authentication Server. In some cases, vendors can provide specific custom
  command regex rules to allow/disallow commands to provide RADIUS command authorization.

RADIUS vs TACACS+
The primary functional difference between RADIUS and TACACS+ is that TACACS+ separates out the
Authorization functionality, where RADIUS combines both Authentication and Authorization.
RADIUS can include privilege information in the authentication reply; however, it can only provide
the privilege level, which means different things to different vendors. Because there is no
standard between vendor implementations of RADIUS authorization, each vendor’s attributes often
conflict, resulting in inconsistent results. Even if this information were consistent, the
administrator would still need to manage the privilege level for commands on each device. This will
quickly become unmanageable. RADIUS doesn’t log the commands used by the administrator. It will
only log the start, stop, and interim records of that session. This means that if there are two or
more administrators logged at any one time, there is no way to tell from the RADIUS logs which
administrator entered which commands.

## Design drivers

### Assumptions

- TACACS+/RADIUS servers should be able to provide role-based and user-based authorization information
   about an user.
- TACACS+/RADIUS Authenticated users are remote users need not be configured with the switch. So
  these TACACS+/RADIUS Authenticated users will map to a default remote user profile after TACACS+/RADIUS
  Authentication.
- If TACACS+ returns a privilege level between 2-13, then the user would be put under privilege
  level of operator.

### Limitations

- TACACS+/RADIUS Authentication/Authorization will not be used for REST/WebUI user login. However
  REST Authentication would work with local users.
- Local Authorization is only supported by means of RBAC Authorization which provides restrictions per user-roles.
  Local Authorization also involves local command authorization which should allow dynamic configuration
  of priv-levels to commands. This is unsupported.
- RADIUS command Authorization is not supported.
- TACACS+/RADIUS Accounting will not be supported.

### Design choices

- By default SSH public key authentication and password authentication is enabled.
- Channel name 'default' refers to (console/ssh) channel. User cannot configure different channels
  with different AAA mechanisms.
- Authentication is supported with TACACS+ and RADIUS for 'default' channel.
- Authentication is not supported with TACACS+ using REST interface. Packaged/Locally configured
  users using `user add` vtysh command are authenticated using REST interface.
- Authorization is supported with TACACS+ only for 'default' channel.
- 'local' Authentication method or Local Authentication is enabled by default for 'default' channel.
- 'none' Authorization refers to Role Based Access Control Authorization. This is enabled by
  default for 'default' channel.
- RADIUS and TACACS+ AAA mechanisms would not be enabled by default.
- 'tacacs_plus' AAA server group contains all the configured TACACS+ servers.
- 'radius' AAA server group contains all the configured RADIUS servers.
- Configured AAA server groups cannot use 'local', 'none', 'tacacs_plus', 'radius' as a group name.
- 'local', 'none', 'tacacs_plus' and 'radius' AAA server groups cannot be configured/unconfigured
  and refers to default family based AAA server groups.
- TACACS+/RADIUS server can be included with only one user defined AAA server group. It would be
  always part of the default family based AAA server groups.
- TACACS+/RADIUS server reachability is supported over management interface (OOBM) or data ports.
  By default OOBM is used.
- TACACS+ users can be mapped roles of operator (at privilege level 1), netop (at privilege level
  14) or admin (at privilege level 15)
- RADIUS users can be mapped to use Administrative (6) and NAS-Prompt (7) to assign the user to the
  admin and operator roles, respectively.
- `none` authorization as the primary method of authorization is considered default and if the user
  configures `aaa authorization commands default none group <group_name>` then the configuration is
  disallowed from CLI/REST.

#### Scalability

- Total of 64 TACACS+ servers can be configured.
- Total of 64 RADIUS servers can be configured.
- Total of 28 user defined AAA server groups can be configured.
- Any number of preconfigured TACACS+/RADIUS servers upto 64 servers can be configured within a AAA
server group.

## Participating modules

```
            +-------+  +---------+                                   AAA Configuration
            |  SSH  |  | Console |                                    +-------------+
            +---+---+  +----+----+                                    |             |
                |           |                                         |   CLI/REST  |
                |           |                                         |             |
                |           |                                         +-----+-------+
                v           v                                               |
+---+--------------------------------+                                      |
|                                    |     +-------------+            +-----v-------+
|             +---------------+      |     |    AAA      |            |             |
|             |     PAM       | <----------+   PAMCFG    | <----------+   OVSDB     |
|             |  Libraries    |      |     |   Daemon    |            |             |
|             +-------+-------+      |     +-------------+            +-------------+
|                     |              |
|  AUTHENTICATION     |              |
+------------------------------------+
                      |
+---------------------V--------------+
|             +---------------+      |     +-------------+
|             |               |      |     |   ops-rbac  |
|             |  VTYSH (CLI)  | <--------->+   Libraries |
|             |               |      |     +-------------+
|             +---------------+      |
|   COMMAND                          |
|  AUTHORIZATION                     |
+------------------------------------+
```

## Solution

### Description

This section provides information on how a user login process would work when AAA is enabled to
provide Authentication/Authorization service.

### Workflows

#### High level workflow for User Authentication + Command Authorization

```
                   User login to the switch
                              |
                 +------------v--------------+
                 |   User credentials are    | -> Connects to TACACS+/RADIUS servers
                 |         Authenticated     |    for Authenticating user
                 +------------+--------------+
                              |
               +--------------v---------------+
               |  Privilege level association | -> Retrieves Privilege level info from
               |                              |       TACACS+/RADIUS which helps doing
               +--------------+---------------+    Privilege level Authorization.
                              |
               +---------------v--------------+
               |   User gets RBAC restricted  |
+------+------->          VTYSH shell         |
|      |       +--------------+---------------+
|      |                      |
|   +--+--+    +--------------v--------------+
|   |Error|    |    User enters a command    |
|   +--^--+    +--------------+--------------+
|      |                      |
|      |  No   +--------------v----------------+
|      +-------+  Command Authorization module | --> Connects to TACACS+ servers to do
|              +--------------+----------------+     Command Authorization
|                              |
|                              |
|                             |  Command is allowed for user in this privilege level
|              +--------------v--------------------------+
+--------------+  User is allowed to execute the command |
               +-----------------------------------------+
```

### Source Interface workflow
If source interface is configured for tacacs using 'ip source-interface tacacs/radius <address/interface> vrf <vrf name>' command, then
the following workflow would be triggered.

```
+------------------+      +----------------------+
| User SSH Login   |      |                      |
|                  |      | ip source+interface  |
|                  |      | tacacs/radius <>     |
+--------+---------+      |                      |
         |                +----------+-----------+
         |                           |                    +----------------------+
 +-------v---------+                 |                    |                      |
 |                 |                 |                    |                      |
 |Username/Password|       +---------v------------+       |                      |
 |prompt           |       |                      |       |                      |
 |                 |       |  AAA Daemon          |       |                      |
 +----------+------+       |                      |       |    Source interface  |
            |              |                      |       |    utils             |
            |              +---+-------^------+---+       |                      |
            |                  |       |      ^           |                      |
            |                  |       |      +-----------+                      |
            |                3)|       |       1)         |                      |
            |                  |       | Source Interface,|                      |
            |                  |       | type             +----------------------+
 +----------+------------------v-----+ |
 | PAM                               | |
 |                                   | |
 |                                   | |                 +------------------------+
 | tac_plus.so server_ip source_ip=  | |                 |                        |
 | 1.1.1.1 namespace=swns            | |                 |                        |
 |                                   | |                 |                        |
 | radius.so server_ip source_ip=    | |                 |                        |
 | 1.1.1.1 namespace=swns            | |                 |                        |
 |                                   | +-----------------+        VRF Utils       |
 +-------------------+---------------+    source_ip,     |                        |
                     |                    namespace      |                        |
                     |                       2)          |                        |
                     |                                   |                        |
                     |                                   |                        |
                     |                                   |                        |
                     |                                   |                        |
                     |                                   +------------------------+
  +------------------v--------------------------+
  |                                             |
  |  Radius/tacacs PAM                          |
  |                                             |
  |  set the source_ip                          |
  |  switch to the namespace, initiate          |
  |      connection to the server               |
  |  switch back to default namespace           |
  |                                             |
  |                                             |
  |                                             |
  |                                             |
  +--------------------------+------------------+
                             |
                             |
                             |
                             |
               +-------------v---------------+
               |                             |
               |     Auth pass/fail          |
               |                             |
               +-----------------------------+
```

#### User Authentication during Login

```
                               User SSH login
                                      +
                                      |
                                      |      +--------------------------------+
                                      |      |if user has used ssh keys, check|
                                      |------>+if the key exists with         |
                                      |      |authorized keys                 |
                                      |      +--------------------------------+
                                      |                    |
                             +--------v-----------+   If no such key exists
                             |  Username and      |        |
                             |  password prompt   |<-------|
                             +--------+-----------+
                                      |
                                      v
+---------------------+      +--------+-----------+      +----------------+
|Get default remote   |  NO  |      Is user       | YES  |Get uid/gid     |
|user uid/gid home dir+------>   locally present? <------+Home dir info   |
|from /etc/passwd     |      |                    |      |from /etc/passwd|
+---------------------+      +--------------------+      +----------------+
                                     |
                                     |
                                     <-----------------------------------------------+
                                     |                                               |
+--------------------------+---------v---------+---------------------------------+   |
PAM Authentication module  |   SSH PAM config  |                                 |   |
|                          |     module load   |                                 |   |
|                          |                   |                                 |   |
|                          +-------------------+                                 |   |
|            +-------------------------------------------------+                 |   |
|    +-------v-----------+  +--------v-----------+   +---------v-------+         |   |
|    |PAM TACACS+        |  |  PAM RADIUS        |   | PAM Local       |         |   |
|    |Authentication     |  |  Authentication    |   | Authentication  |         |   |
|    |with pam_tacplus.so|  |  with pam_radius.so|   | with pam_unix.so|         |   |
|    +-------+-----------+  +--------+-----------+   +------+----------+         |   |
|            |                       |                      |                    |   |
|            v                       v                      v                    |   |
|      Reaches to TACACS+     Reaches to RADIUS       Checks local               |   |
|      Server for checking    Server for checking     /etc/passwd to             |   |
|      user credentials       user credentials        validate user/pass         |   |
|                                                                                |   |
|                                                                                |   |
+-------------------------------------+------------------------------------------+   |
                                      |                                              |
                          +-----------v--------------+                               |
                  +-------v---------+        +-------v------+                        |
                  |  Authentication |        |Authentication|                        |
                  |      SUCCESS    |        |    FAIL      |                        |
                  +-----------------+        +--------------+                        |
                          |                  +-------v-----------+                   |
                  +----------------+         |  Retry password   +-------------------+
                  |      vtysh     |         |     3 times       |
                  +----------------+         +-------------------+
```

#### Fallback Mechanism for Authentication (Default mode)

Following actions take place when a user login occurs with `aaa authentication login default group
<group_name>` configured on the switch.

1. A TACACS+/RADIUS user SSH' to the switch and is put into a login prompt
2. SSHd accepts connection request and process it by asking for username and password credentials.
3. SSHd checks if the user has used SSH keys then the key used is checked against authorized keys.
   the user is locally present with /etc/passwd, in this case because he's a
   TACACS+/RADIUS user - the user would not be locally configured/available.
4. SSHd recognizes the TACACS+/RADIUS user is not locally available so it uses a locally configured
remote user profile 'remote_user' for this user.
5. SSHd loads the PAM configuration specified for this process/daemon from /etc/pam.d/
6. Based on the PAM configuration within /etc/pam.d/sshd it would have a sample PAM auth
configuration [Sample configuration output reference]
7. PAM configuration would be updated based on the configured user AAA primary and fallback
mechanisms.
   - In this sample configuration we have TACACS+ server as the primary, RADIUS server as the
secondary and  finally local authentication as the last method.
8. The configured TACACS+/RADIUS servers is reached out to validate the user credentials. The next
step can fall under the following scenarios:
   - Scenario1: if TACACS+/RADIUS server is reachable and has the user configured with the same
password - then PAM libraries would return PAM_SUCCESS to the application (SSHd).
   - Scenario2: If TACACS+/RADIUS server is unreachable - then PAM libraries would continue to next
configured TACACS+/RADIUS server available with the PAM configuration.
   - Scenario3: If TACACS+/RADIUS server is reachable but TACACS+/RADIUS does not have the user
account or has different user credentials. Then the TACACS+/RADIUS server return an Authentication
Failure message. Based on this, the PAM libraries would return PAM_AUTH_ERR to the application
(SSHd). This will immediately terminate further processing of PAM configuration and return
PAM_AUTH_ERR to the application.
9. During Authentication, once authentication is successful - the PAM libraries fetch information
about the privilege level association with the user. Based on the privilege level association, the
user is provided access to RoleBasedAccessControl restricted `vtysh` shell.
10. During Authentication, if authentication is unsuccessful - user is asked to enter his password
again. Maximum of 3 password retries are allowed.
11. If the privilege level of the user is not among the well defined privilege levels as defined
[here]#Privilege-level-to-user-role-map then he is put onto the next lowest privilege level. For
example, if user privilege level returned from TACACS+ server is between 2-13, then that user is
put on a privilege level of 1.

12. Once Authentication is successful, user is provided access to `vtysh` shell.

#### Failthrough Mechanism for Authentication

Following actions take place when a user login occurs with `aaa authentication login
allow-failthrough` and`aaa authentication login default` configured on the switch.
1. All the above steps till step 8 will happen. Scenario1, Scenario2, and the only difference is with
 Scenario3: If TACACS+/RADIUS server is reachable but TACACS+/RADIUS does not have the user
account or has different user credentials. Then the TACACS+/RADIUS server return an Authentication
Failure message. Based on this, the PAM libraries would return PAM_AUTH_ERR to the PAM framework.
     - PAM framework because of the PAM configuration provided decides to go to next authentication
configuration which could be either RADIUS/TACACS+/LOCAL authentication method. And it would
execute step 8 over all for the next authentication method.
     - Only when all the Authentication methods mentioned as part of PAM configuration for SSH are
covered, and if there is no SUCCESS, then a PAM_AUTH_ERR is returned to the application (SSHd).
2. Rest of the steps remain same as described above with 'fallback case'.
    Once Authentication is successful, user is provided access to `vtysh` shell.

#### User Command Authorization

Following action take place when a user login occurs with `aaa authorization commands default`
configured on the switch. Please note that this is applicable only for TACACS+ server configuration.

1. A TACACS+/RADIUS user tries to SSH to the switch. He is put through the steps metioned above for
TACACS+/RADIUS Authentication.
2. Once user is provided access to `vtysh` shell prompt, this is where the TACACS+ command
authorization module gets activated.
3. For each command entered by the user, the command is sent to the TACACS+ server with username
information to validate if this command is authorized for this user. The next step can fall under
the following scenarios:
   - Scenario1: If TACACS+ server is reachable and has this command allowed for this user - then
the switch would receive a TAC_PLUS_AUTHOR_STATUS_PASS which would trigger the command
authorization module on the switch to allow execution of the command and the command would be
executed on the switch.
   - Scenario2: If TACACS+ server is reachable and has this command **not** allowed for this user -
then the switch would receive a TAC_PLUS_AUTHOR_STATUS_FAIL which would trigger the command
authorization module on the switch to print "Cannot execute command. Command not allowed" on
`vtysh` output.
   - Scenario3: If first TACACS+ server is unreachable, then reachability with the subsequent
TACACS+ servers are tried.
     - If `none` authorization is configured as fallback, it refers to doing RoleBasedAccessControl
restriction for the user at the privilege level provided by the TACACS+/RADIUS servers during
authentication or the local user group privileges associated with this user.
     - If `none` authorization is **not** configured as fallback, then until the TACACS+ servers
are reachable again the user cannot execute any command on the switch. More about how `none`
provides that fail safe, is described [here]#none+authorization
    - Scenario4: All the TACACS+ server were unreachable and 'none' authorization is not configured
as fallback. Then the command authorization module would print
"Cannot execute command. Could not connect to any TACACS+ servers."

### Privilege level to user role map

The following privilege level to role map are cascaded privilege levels mapping, a role with a
higher privilege level has access to all the elements which are under lower privilege level as is
the example described for ops_admin and ops_netop.

| Configured user role | TACACS+ privilege level | RADIUS privilege level | ADDITIONAL INFO                         |
| -------------------- | ----------------------- | ---------------------- |---------------------------------------- |
| ops_admin            | 15                      | ADMINISTRATIVE (6)     | Has access to all commands under PRIV-LVL-14 and special admin commands
                                                                              'reboot', 'start-shell' and 'user add/delete'
                                                                              and 'show user-list' |
| ops_netop            | 14                      |  -                     | Has access to all 'enable' and 'config' mode CLI commands. |
| ops_operator         | 1                       | NAS-Prompt (7)         | Has access to only 'view' mode CLI commands. |

The privilege level noted for RADIUS is as per the Service-Type attribute with RADIUS configuration, as defined in RFC 2865.

## OVSDB-Schema

High level information of the tables and columns used by AAA.

`System` table: Stores System level information of the switch.
- `aaa` column : Stores information about the global AAA configurations. Supports globally setting
  - `fail_through` to indicate that we follow through next AAA server mechanism if there is
authentication failure with the active AAA server.
  - `radius_timeout` interval to use for each RADIUS server before declaring a timeout failure.
  - `radius_passkey` to specify a global default 'passkey' to use with RADIUS servers.
  - `radius_auth`  to use 'pap' or 'chap' as the authentication method type for RADIUS.
  - `radius_retries` to specify number of retries before claiming a RADIUS server to be dead.
  - `tacacs_timeout` interval to use for each TACACS+ server before declaring a timeout failure.
  - `tacacs_passkey` to specify a global default 'passkey' to use with TACACS+ servers.
  - `tacacs_auth` to use 'pap' or 'chap' as the authentication method type for TACACS+.
  - `ssh_publickeyauthentication_enable` to enable/disable SSH public key authentication.
  - `ssh_passkeyauthentication_enable` to enable/disable password based authentication.

`Tacacs_Server` table: Stores TACACS+ Servers and related information. This table is indexed using
`address` and `tcp_port`. Each configured TACACS+ server will have its own row within this
table. This table contains the following information:
- `address` column to store the FQDN/IPv4/IPv6 TACACS+ server.
- `tcp_port` column to store the configured TCP port to be used for connecting to the TACACS+
server.
- `passkey` column to store the configured 'passkey' to use with TACACS+ server.
- `timeout` column to store the interval to use for the TACACS+ server.
- `auth_type` column to store information on whether to use 'pap' or 'chap' to use as the
authentication method type.
- `group` column to store information on which AAA server group the TACACS+ server belongs to.
Default TACACS+ server group is 'tacacs_plus'.
- `user_group_priority` column to store information on the priority of the TACACS+ server within the
`group`.
- `default_group_priority` column to store information on the priority of the TACACS+ server within the
default AAA server group 'tacacs_plus'.

`Radius_Server` table: Stores RADIUS Servers and related information. This table is indexed using
`address` and `udp_port`. Each configured RADIUS server will have its own row within the table.
This table contains the following information:
- `address` column to store the FQDN/IPv4 RADIUS server.
- `udp_port` column to store the configured UDP port to be used for connecting to the RADIUS server.
- `passkey` column to store the configured 'passkey' to use with RADIUS server.
- `timeout` column to store the interval to use for the RADIUS server.
- `auth_type` column to store information on whether to use 'pap' or 'chap' to use as the
authentication method type.
- `group` column to store information on which AAA server group the RADIUS server belongs to.
Default RADIUS server group is 'radius'.
- `user_group_priority` column to store information on the priority of the RADIUS server within the
`group`.
- `default_group_priority` column to store information on the priority of the RADIUS server within the
default AAA server group 'radius'.
- `retries` column to store information on the number of retries to RADIUS server before the system
timeout occurs for this server.

`AAA_Server_Group` table: Stores information on the configured and internal AAA Server Groups. This
table is indexed using `group_name`. Each configured AAA Server Group will have its own row within
the table. This table contains the following information:
- `group_type` column to store the protocol family of the group and can take values as 'radius',
'tacacs_plus', 'none', 'local'.
- `group_name` column to store the configured AAA server group name.
- `is_static` column to indicate whether this is a configured AAA server or internal AAA server
group.

`AAA_Server_Group_Prio` table: Stores information on the configured sequence for Authentication and
Authorization mechanism. This table is indexed using the channel name. This table contains the
following information:
- `session_type` column to store the channel name information. Currently only `default` channel is
supported.
- `authentication_group_prios` column to store the sequence/order of the AAA server groups to be
used for Authentication.
- `authorization_group_prios` column to store the sequence/order of the AAA server groups to be
used for Authorization.

Please refer to the extended schema for additional information on each of the fields.

## Design Details

### Configuration Workflow

- The `ops-aaautilspamcfg` daemon registers to OVSDB columns and tables and listens to the changes
of those columns and tables. The OVSDB tables and columns mentioned [here]#OVSDB-Schema are
registered by the `ops-aaautilspamcfg` daemon.
- When the `ops-aaautilspamcfg` daemon gets a change notification in the OVSDB, it performs the
following tasks:
  - SSH configuration update:
    - Modifies the SSH configuration file `/etc/ssh/sshd_config` if there is a change in the `aaa`
column for `pub_key_authentication` or `password_authentication` key.
  - TACACS+/RADIUS configuration updates:
    - When `ops_aaautilspamcfg` daemon starts for the first time
      -  it populates `AAA_Server_Group` table with statically available groups such as
`tacacs_plus/radius/none/local` .
      - it populates `AAA_Server_Group_Prio` table with default `local` authentication and default
`none` authorization.
      - it populates global parameters like `timeout/passkey/auth_type`with default values within
the `aaa` column of `System` table.
    - If a user issues `aaa authentication login default group <group_name>` or TACACS+ server or
RADIUS server configuration. Group name can be `local`/`tacacs_plus`/`radius` or any user defined
AAA server group. The following scenarios arise:
      - The user configures list of AAA server groups in the order in which authentication needs to
be applied for a specific channel. This triggers a notification through `AAA_Server_Group_Prio`
table.
      - `ops_aaautilspamcfg` daemon gets information from the `authentication_group_prios` column
for the specified channel.
        - It returns a KV pair, which is sorted based on the priority of the configured server
groups.
      - For every server group, the daemon looks into `Tacacs_Server`/`Radius_Server` table and
checks for TACACS+/RADIUS servers belonging to that group. This TACACS+/RADIUS server list is again
sorted based on the `default_priority` column for family based groups or `group_priority` column
for user defined groups.
      - If attributes such as `timeout`, `passkey`, `auth_type` are **not** available within
`Tacacs_Server`/`Radius_Server` then these values are picked from the `System` table from `aaa`
column.
      - For each of the servers configured it would translate to PAM configuration entries within
`/etc/pam.d/ssh_auth_access`as follows:
        - For `local` group the daemon configures PAM configuration file with `pam_unix.so` as the
authentication method.
        - For `tacacs_plus` group the daemon configures PAM configuration file with
`/usr/lib/security/libpam_tacplus.so` as the authentication method.
        - For `radius` group the daemon configures PAM configuration file with
`/usr/lib/security/libpam_radius.so` as the authentication method.
      - By default any last authentication method is defined with `[success=1 default=ignore]` PAM
flags.
      - If fallback authentication is configured then the servers include `[success=done
new_authtok_reqd=done default=ignore auth_err=die]` PAM flags.
      - If failthrough authentication is configured then the server include `[success=done
new_authtok_reqd=done default=ignore]` PAM flags.
    - If the user has configured 'ip source-interface tacacs_plus/radius <address/interface> vrf <vrf name>'
      then it would go through the above steps but will use the source_ip, destination_namespace
      derived from the VRF table:
      - AAA daemon waits for the notification from VRF table on the tacacs/radius source interface configuration
      - When the source interface is configured, AAA daemon invokes the source interface utils python module to
        get the interface and the interface type
        Vrf utils Python module is then invoked:
        1. to get the network namespace corresponding to the default VRF and 
        2. to get the source ip address
        3. if the interface type returned above corresponds to an interface name,
           then the primary address configured on the interface is selected. 
        4. if the primary address is not configured, then the lowest secondary address is used
        - For more info refer to (source_intf_usage_guide)[http://git.openswitch.net/cgit/openswitch/ops/tree/docs/source_interface_user_guide.md]
      - After retrieving source ip and source namespace it is configured with the pam config files with keywords
        'dstn_namespace' and 'source_ip'.

### Local Authentication

Local Authentication refers to Authentication using /etc/passwd and /etc/shadow files.

### None Authorization

None Authorization refers to Authorization using RoleBasedAccessControl.

### SSH public key authentication
We have SSH public key authentication and password authentication enabled by default.

### Internal Components

#### Sample PAM configuration files

#### TACACS+ PAM configuration with fallback mechanism to RADIUS and then to local for
Authentication
```
auth    [success=done new_authtok_reqd=done default=ignore auth_err=die]
/usr/lib/security/libpam_tacplus.so     debug server=1.1.1.1:49 secret=tacacs_sharedkey login=pap
timeout=5

auth    [success=done new_authtok_reqd=done default=ignore auth_err=die]
/usr/lib/security/libpam_radius.so     debug server=172.17.0.3:1812 secret=radius_sharedkey
login=pap timeout=5 retries=2

auth    [success=1 default=ignore]      pam_unix.so nullok

# here's the fallback if no module succeeds
auth    requisite                       pam_deny.so
auth    required                        pam_permit.so
```

#### TACACS+ PAM configuration with `fail_through` mechanism to RADIUS and then to local for
Authentication
```
auth    [success=done new_authtok_reqd=done default=ignore]
/usr/lib/security/libpam_tacplus.so     debug server=1.1.1.1:49 secret=tacacs_sharedkey login=pap
timeout=5

auth    [success=done new_authtok_reqd=done default=ignore]
/usr/lib/security/libpam_radius.so     debug server=172.17.0.3:1812 secret=radius_sharedkey
login=pap timeout=5 retry=2

auth    [success=1 default=ignore]      pam_unix.so nullok
# here's the fallback if no module succeeds
auth    requisite                       pam_deny.so
auth    required                        pam_permit.so
```

### TACACS+ PAM configuration with 'ip source-interface' configuration
```
auth    [success=done new_authtok_reqd=done default=ignore]
/usr/lib/security/libpam_tacplus.so     debug server=1.1.1.1:49 secret=tacacs_sharedkey login=pap
timeout=5 dstn_namespace=swns source_ip=172.17.0.5

auth    [success=done new_authtok_reqd=done default=ignore]
/usr/lib/security/libpam_radius.so     debug server=172.17.0.3:1812 secret=radius_sharedkey
login=pap timeout=5 retry=2 dstn_namespace=swns source_ip=172.17.0.5

auth    [success=1 default=ignore]      pam_unix.so nullok
# here's the fallback if no module succeeds
auth    requisite                       pam_deny.so
auth    required                        pam_permit.so
```

### Interaction with Platform Dependent code

Does not interact with platform dependent code.

## Standard Reference

| Standard | Level of compliance | Reference                                |
| -------- | ------------------- | ---------------------------------------- |
| TACACS+  |                     | https://tools.ietf.org/html/draft-grant-tacacs-02 |
| RADIUS   |                     | https://tools.ietf.org/html/rfc2865, https://tools.ietf.org/html/rfc2866 |
| AAA      |                     | https://tools.ietf.org/html/rfc2903      |
