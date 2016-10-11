# TACACS+ Authentication Feature Test Cases

## Contents

- [Test local authentication](#test-local-authentication)
	- [Local authentication user and password](#local-authentication-user-and-password)
	- [Local authentication user and incorrect password](#local-authentication-user-and-incorrect-password)
	- [Local authentication non-existent user](#local-authentication-non-existent-user)
- [Test TACACS+ authentication](#test-tacacs-authentication)
	- [TACACS+ authentication user and password](#tacacs-authentication-user-and-password)
	- [TACACS+ authentication user and incorrect password](#tacacs-authentication-user-and-incorrect-password)
	- [TACACS+ authentication non-existent user](#tacacs-authentication-non-existent-user)
	- [TACACS+ authentication incorrect password once](#tacacs-authentication-incorrect-password-once)
	- [TACACS+ authentication timeout](#tacacs-authentication-timeout)
	- [TACACS+ authentication passkey](#tacacs-authentication-passkey)
- [Test authentication with fail-through](#test-authentication-with-fail-through)
	- [TACACS+ authentication user login without fail-through](#tacacs-authentication-user-login-without-fail-through)
	- [TACACS+ authentication user login with fail-through](#tacacs-authentication-user-login-with-fail-through)
	- [Local authentication first priority with fail-through](#local-authentication-first-priority-with-fail-through)
	- [Local authentication second priority with fail-through](#local-authentication-second-priority-with-fail-through)
	- [Local authentication last priority with fail-through](#local-authentication-last-priority-with-fail-through)
- [Test no authentication option](#test-no-authentication-option)
	- [No authentication option_user and password](#no-authentication-option-user-and-password)
	- [No authentication option_user and incorrect password](#no-authentication-option-user-and-incorrect-password)
	- [No authentication option_non-existent user](#no-authentication-option-non-existent-user)
- [IPv6 test](#ipv6-test)
	- [TACACS+ authentication IPv6 user login](#tacacs-authentication-ipv6-user-login)
- [Test source interface option](#test-source-interface-option)
	- [Interface address as the source interface](#interface-address-as-the-source-interface)
	- [Interface name as the source interface](#interface-name-as-the-source-interface)
	- [Loopback address as the source interface](#loopback-address-as-the-source-interface)
	- [Loopback name as the source interface](#loopback-name-as-the-source-interface)
	- [OOBM address as the source interface](#oobm-address-as-the-source-interface)
	- [No source interface configuration](#no-source-interface-configuration)
- [Test TACACS+ command authorization](#test-tacacs-command-authorization)
	- [Set none as TACACS+ command authorization and test command authorization](#set-none-as-tacacs+-command-authorization-and-test-command-authorization)
	- [Set TACACS+ groups and none as TACACS+ cmd authorization and test command authorization] (#set-tacacs+-groups-and-none-as-tacacs-cmd-authorization-and-test-command-authorization)
	- [SSH to switch as a remote TACACS+ user and test command authorization](#ssh-to-switch-as-a-remote-tacacs+-user-and-test-command-authorization)
        - [Set unreachable TACACS+ server for TACACS+ cmd authorization and test cmd authorization](#set-unreachable-tacacs+-server-for-tacacs+-cmd-authorization-and-test-cmd-authorization)


## Test local authentication

### Local authentication user and password

#### Objective
This test case validates if user able to login to switch with correct username/password and local authentication enabled

#### Requirements
- Docker: Up-to-date OpenSwitch docker image and two pre-configured openswitch/tacacs_server image
- Physical: AS5712 switch loaded with up-to-date OpenSwitch image, two TACACS+ servers loaded with pre-configured openswitch/tacacs_server image

#### Setup

##### Topology diagram
```ditaa
+----------+   +----------+   +----------+
|  Host 1  +---+  Switch  +---+  Host 1  |
+----------+   +----------+   +----------+
```

##### Test Setup

##### **Authentication client (OpenSwitch) setup**
1. Add user netop (password: netop) to swith
2. Configure the switch as Authentication client
```
configure terminal
aaa authentication login default local
```

#### Test result criteria

##### Test pass criteria
Local user netop (password: netop) able to pass local authentication and login to OpenSwitch

##### Test fail Criteria
Local user netop failed to login after provide password three times


### Local authentication user and incorrect password

#### Objective
This test case validates if user login fails with correct username/incorrect password and local authentication enabled

#### Requirements
- Docker: Up-to-date OpenSwitch docker image and two pre-configured openswitch/tacacs_server image
- Physical: AS5712 switch loaded with up-to-date OpenSwitch image, two TACACS+ servers loaded with pre-configured openswitch/tacacs_server image

#### Setup

##### Topology diagram
```ditaa
+----------+   +----------+   +----------+
|  Host 1  +---+  Switch  +---+  Host 1  |
+----------+   +----------+   +----------+
```
##### Test Setup

##### **Authentication client (OpenSwitch) setup**
1. Add user netop (password: netop) to swith
2. Configure the switch as Authentication client
```
configure terminal
aaa authentication login default local
```

#### Test result criteria

##### Test pass criteria
Local user netop failed to login after provide password three times

##### Test fail criteria
Local user netop (password: dummy) able to pass local authentication and login to OpenSwitch


### Local authentication non-existent user

#### Objective
This test case validates if user login fails with non-existent user and local authentication enabled

#### Requirements
- Docker: Up-to-date OpenSwitch docker image and two pre-configured openswitch/tacacs_server image
- Physical: AS5712 switch loaded with up-to-date OpenSwitch image, two TACACS+ servers loaded with pre-configured openswitch/tacacs_server image

#### Setup

##### Topology diagram
```ditaa
+----------+   +----------+   +----------+
|  Host 1  +---+  Switch  +---+  Host 1  |
+----------+   +----------+   +----------+
```
##### Test Setup

##### **Authentication client (OpenSwitch) setup**
1. Add user netop (password: netop) to swith
2. Configure the switch as Authentication client
```
configure terminal
aaa authentication login default local
```

#### Test result criteria

##### Test pass criteria
Non-existent user dummy (password: dummypasswd) failed to login after provide password three times

##### Test fail criteria
Non-existent user dummy (password: dummypasswd) able to pass local authentication and login to OpenSwitch


## Test TACACS+ authentication

### TACACS+ authentication user and password

#### Objective
This test case validates if user able to login to switch with correct username/password and TACACS+ server authentication enabled

#### Requirements
- Docker: Up-to-date OpenSwitch docker image and two pre-configured openswitch/tacacs_server image
- Physical: AS5712 switch loaded with up-to-date OpenSwitch image, two TACACS+ servers loaded with pre-configured openswitch/tacacs_server image

#### Setup

##### Topology diagram
```ditaa
+----------+   +----------+   +----------+
|  Host 1  +---+  Switch  +---+  Host 1  |
+----------+   +----------+   +----------+
```

##### Test Setup

##### **TACACS+ server setup**
1. Disable TACACS+ service on two hosts
```
service tac_plus stop
```
2. Configure passkey(authentication key) on both host, passkey should show up in
   **/etc/tacacs/tac_plus.conf** as following:
```
key = "tac_test"
```
3. Create user user1 on host 1, user1 should show up in **/etc/tacacs/tac_plus.conf** as following:
```
  user = user1 {
        pap = cleartext user1
        service = exec {
         priv-lvl = 14
        }
  }
```
4. Enable TACACS+ service on two hosts
```
service tac_plus start
```

##### Authentication client (OpenSwitch) setup
1. Get ip address of two hosts
2. Configure the switch as TACACS+ authentication client and add two TACACS+ hosts
```
configure terminal
tacacs-server key tac_test
tacacs-server host 172.17.0.2
tacacs-server host 172.17.0.3 key tac_test auth-type chap
aaa group server tacacs+ sg1
(config-sg) server 172.17.0.2
exit
aaa group server tacacs+ sg2
(config-sg) server 172.17.0.3
exit
aaa authentication login default group sg1
```

#### Description
User should be able to pass TACACS+ server group authentication and login to switch use
username/password configured on primary TACACS+ server

#### Test result criteria

##### Test pass criteria
User user1 (password: user1) able to pass TACACS+ server authentication and login to OpenSwitch

##### Test fail criteria
User user1 (password: user1) failed to login after provide password three times


### TACACS+ authentication user and incorrect password

#### Objective
This test case validates if user login fails with correct username/incorrect password and TACACS+ server authentication enabled

#### Requirements
- Docker: Up-to-date OpenSwitch docker image and two pre-configured openswitch/tacacs_server image
- Physical: AS5712 switch loaded with up-to-date OpenSwitch image, two TACACS+ servers loaded with pre-configured openswitch/tacacs_server image

#### Setup

##### Topology diagram
```ditaa
+----------+   +----------+   +----------+
|  Host 1  +---+  Switch  +---+  Host 1  |
+----------+   +----------+   +----------+
```

##### Test Setup

##### **TACACS+ server setup**
1. Disable TACACS+ service on two hosts
```
service tac_plus stop
```
2. Configure passkey(authentication key) on both host, passkey should show up in
   **/etc/tacacs/tac_plus.conf** as following:
```
key = "tac_test"
```
3. Create user user1 on host 1, user1 should show up in **/etc/tacacs/tac_plus.conf** as following:
```
  user = user1 {
        pap = cleartext user1
        service = exec {
         priv-lvl = 14
        }
  }
```
4. Enable TACACS+ service on two hosts
```
service tac_plus start
```

##### Authentication client (OpenSwitch) setup
1. Get ip address of two hosts
2. Configure the switch as TACACS+ authentication client and add two TACACS+ hosts
```
configure terminal
tacacs-server key tac_test
tacacs-server host 172.17.0.2
tacacs-server host 172.17.0.3 key tac_test auth-type chap
aaa group server tacacs+ sg1
(config-sg) server 172.17.0.2
exit
aaa group server tacacs+ sg2
(config-sg) server 172.17.0.3
exit
aaa authentication login default group sg1
```

#### Description
User should not be able to pass TACACS+ server group authentication use username/incorrect password

#### Test result criteria

##### Test pass criteria
User user1 (password: dummy) failed to login after provide password three times

##### Test fail criteria
User user1 (password: dummy) able to pass TACACS+ server authentication and login to OpenSwitch


### TACACS+ authentication non-existent user

#### Objective
This test case validates if user login fails with non-existent user and TACACS+ server authentication enabled

#### Requirements
- Docker: Up-to-date OpenSwitch docker image and two pre-configured openswitch/tacacs_server image
- Physical: AS5712 switch loaded with up-to-date OpenSwitch image, two TACACS+ servers loaded with pre-configured openswitch/tacacs_server image

#### Setup

##### Topology diagram
```ditaa
+----------+   +----------+   +----------+
|  Host 1  +---+  Switch  +---+  Host 1  |
+----------+   +----------+   +----------+
```

##### Test Setup

##### **TACACS+ server setup**
1. Disable TACACS+ service on two hosts
```
service tac_plus stop
```
2. Configure passkey(authentication key) on both host, passkey should show up in
   **/etc/tacacs/tac_plus.conf** as following:
```
key = "tac_test"
```
3. Create user user1 on host 1, user1 should show up in **/etc/tacacs/tac_plus.conf** as following:
```
  user = user1 {
        pap = cleartext user1
        service = exec {
         priv-lvl = 14
        }
  }
```
4. Enable TACACS+ service on two hosts
```
service tac_plus start
```

##### Authentication client (OpenSwitch) setup
1. Get ip address of two hosts
2. Configure the switch as TACACS+ authentication client and add two TACACS+ hosts
```
configure terminal
tacacs-server key tac_test
tacacs-server host 172.17.0.2
tacacs-server host 172.17.0.3 key tac_test auth-type chap
aaa group server tacacs+ sg1
(config-sg) server 172.17.0.2
exit
aaa group server tacacs+ sg2
(config-sg) server 172.17.0.3
exit
aaa authentication login default group sg1
```

#### Description
Non-existent user should not be able to pass TACACS+ server group authentication

#### Test result criteria

##### Test pass criteria
Non-existent user dummy (password: dummypasswd) failed to login after provide password three times

##### Test fail criteria
Non-existent user dummy (password: dummypasswd) able to pass TACACS+ server authentication and login to OpenSwitch


### TACACS+ authentication incorrect password once

#### Objective
This test case validates if user able to login to switch with correct username/password in the second try (first try with incorrect password) and TACACS+ authentication enabled

#### Requirements
- Docker: Up-to-date OpenSwitch docker image and two pre-configured openswitch/tacacs_server image
- Physical: AS5712 switch loaded with up-to-date OpenSwitch image, two TACACS+ servers loaded with pre-configured openswitch/tacacs_server image

#### Setup

##### Topology diagram
```ditaa
+----------+   +----------+   +----------+
|  Host 1  +---+  Switch  +---+  Host 1  |
+----------+   +----------+   +----------+
```

##### Test Setup

##### **TACACS+ server setup**
1. Disable TACACS+ service on two hosts
```
service tac_plus stop
```
2. Configure passkey(authentication key) on both host, passkey should show up in
   **/etc/tacacs/tac_plus.conf** as following:
```
key = "tac_test"
```
3. Create user user1 on host 1, user1 should show up in **/etc/tacacs/tac_plus.conf** as following:
```
  user = user1 {
        pap = cleartext user1
        service = exec {
         priv-lvl = 14
        }
  }
```
4. Enable TACACS+ service on two hosts
```
service tac_plus start
```

##### Authentication client (OpenSwitch) setup
1. Get ip address of two hosts
2. Configure the switch as TACACS+ authentication client and add two TACACS+ hosts
```
configure terminal
tacacs-server key tac_test
tacacs-server host 172.17.0.2
tacacs-server host 172.17.0.3 key tac_test auth-type chap
aaa group server tacacs+ sg1
(config-sg) server 172.17.0.2
exit
aaa group server tacacs+ sg2
(config-sg) server 172.17.0.3
exit
aaa authentication login default group sg1
```

#### Description
User should be able to pass TACACS+ server group authentication use username/password after first failed login attempt (with username/incorrect password)

#### Test result criteria

##### Test pass criteria
User user1 (password: user1) able to pass TACACS+ server authentication and login to OpenSwitch

##### Test fail criteria
User user1 (password: user1) failed to login after provide password three times


### TACACS+ authentication timeout

#### Objective
This test case validates user login fails (timeout) when timeout value set to minimum (1 second) and TACACS+ authentication enabled.

#### Requirements
- Docker: Up-to-date OpenSwitch docker image and two pre-configured openswitch/tacacs_server image
- Physical: AS5712 switch loaded with up-to-date OpenSwitch image, two TACACS+ servers loaded with pre-configured openswitch/tacacs_server image

#### Setup

##### Topology diagram
```ditaa
+----------+   +----------+   +----------+
|  Host 1  +---+  Switch  +---+  Host 1  |
+----------+   +----------+   +----------+
```

##### Test Setup

##### **TACACS+ server setup**
1. Disable TACACS+ service on two hosts
```
service tac_plus stop
```
2. Configure passkey(authentication key) on both host, passkey should show up in
   **/etc/tacacs/tac_plus.conf** as following:
```
key = "tac_test"
```
3. Create user user1 on host 1, user1 should show up in **/etc/tacacs/tac_plus.conf** as following:
```
  user = user1 {
        pap = cleartext user1
        service = exec {
         priv-lvl = 14
        }
  }
```
4. Enable TACACS+ service on two hosts
```
service tac_plus start
```

##### Authentication client (OpenSwitch) setup
1. Get ip address of two hosts
2. Configure timeout
```
configure terminal
tacacs-server timeout 1
```
3. Configure the switch as TACACS+ authentication client and add two TACACS+ hosts
```
configure terminal
tacacs-server key tac_test
tacacs-server host 172.17.0.2
tacacs-server host 172.17.0.3 key tac_test auth-type chap
aaa group server tacacs+ sg1
(config-sg) server 172.17.0.2
exit
aaa group server tacacs+ sg2
(config-sg) server 172.17.0.3
exit
aaa authentication login default group sg1
```

#### Description
User should fail to pass TACACS+ authentication due to timeout

#### Test result criteria

##### Test pass criteria
User user1 (password: user1) failed to login

##### Test fail criteria
User user1 (password: user1) able to pass TACACS+ server authentication and login to OpenSwitch

### TACACS+ authentication passkey

#### Objective
This test case validates user login fails when passkey (shared secret) set to mismatch value and TACACS+ authentication enabled.

#### Requirements
- Docker: Up-to-date OpenSwitch docker image and two pre-configured openswitch/tacacs_server image
- Physical: AS5712 switch loaded with up-to-date OpenSwitch image, two TACACS+ servers loaded with pre-configured openswitch/tacacs_server image

#### Setup

##### Topology diagram
```ditaa
+----------+   +----------+   +----------+
|  Host 1  +---+  Switch  +---+  Host 1  |
+----------+   +----------+   +----------+
```

##### Test Setup

##### **TACACS+ server setup**
1. Disable TACACS+ service on two hosts
```
service tac_plus stop
```
2. Configure passkey(authentication key) on both host, passkey should show up in
   **/etc/tacacs/tac_plus.conf** as following:
```
key = "tac_test"
```
3. Create user user1 on host 1, user1 should show up in **/etc/tacacs/tac_plus.conf** as following:
```
  user = user1 {
        pap = cleartext user1
        service = exec {
         priv-lvl = 14
        }
  }
```
4. Enable TACACS+ service on two hosts
```
service tac_plus start
```

##### Authentication client (OpenSwitch) setup
1. Get ip address of two hosts
2. Configure passkey
```
configure terminal
tacacs-server key dummy
```
3. Configure the switch as TACACS+ authentication client and add two TACACS+ hosts
```
configure terminal
tacacs-server key tac_test
tacacs-server host 172.17.0.2
tacacs-server host 172.17.0.3 key tac_test auth-type chap
aaa group server tacacs+ sg1
(config-sg) server 172.17.0.2
exit
aaa group server tacacs+ sg2
(config-sg) server 172.17.0.3
exit
aaa authentication login default group sg1
```

#### Description
User should fail to pass TACACS+ authentication due to passkey mismatch

#### Test result criteria

##### Test pass criteria
User user1 (password: user1) failed to login after three password attempts

##### Test fail criteria
User user1 (password: user1) able to pass TACACS+ server authentication and login to OpenSwitch


## Test authentication with fail-through

### TACACS+ authentication user login without fail-through

#### Objective
This test case validates user (from second priority TACACS+ server) login fails with fail-through disabled and TACACS+ authentication enabled.

#### Requirements
- Docker: Up-to-date OpenSwitch docker image and two pre-configured openswitch/tacacs_server image
- Physical: AS5712 switch loaded with up-to-date OpenSwitch image, two TACACS+ servers loaded with pre-configured openswitch/tacacs_server image

#### Setup

##### Topology diagram
```ditaa
+----------+   +----------+   +----------+
|  Host 1  +---+  Switch  +---+  Host 1  |
+----------+   +----------+   +----------+
```

##### Test Setup

##### **TACACS+ server setup**
1. Disable TACACS+ service on two hosts
```
service tac_plus stop
```
2. Configure passkey(authentication key) on both host, passkey should show up in
   **/etc/tacacs/tac_plus.conf** as following:
```
key = "tac_test"
```
3. Create user user1 on host 1, user1 should show up in **/etc/tacacs/tac_plus.conf** as following:
```
  user = user_chap {
        chap = cleartext use_chap_passwd
        service = exec {
         priv-lvl = 14
        }
  }
```
4. Enable TACACS+ service on two hosts
```
service tac_plus start
```

##### Authentication client (OpenSwitch) setup
1. Get ip address of two hosts
2. Configure the switch as TACACS+ authentication client and add two TACACS+ hosts
```
configure terminal
tacacs-server key tac_test
tacacs-server host 172.17.0.2
tacacs-server host 172.17.0.3 key tac_test auth-type chap
aaa group server tacacs+ sg1
(config-sg) server 172.17.0.2
exit
aaa group server tacacs+ sg2
(config-sg) server 172.17.0.3
exit
aaa authentication login default group sg1 sg2
```
3. Disable fail-through option
```
configure terminal
no aaa authentication allow-fail-through
```

#### Description
User should fail to pass TACACS+ authentication due to fail-through disabled

#### Test result criteria

##### Test pass criteria
User user_chap (password: user_chap_passwd) failed to login after three password attempts

##### Test fail criteria
User user_chap (password: user_chap_passwd) able to pass TACACS+ server authentication and login to OpenSwitch

### TACACS+ authentication user login with fail-through

#### Objective
This test case validates user (from second priority TACACS+ server) able to login to switch with TACACS+ server authentication and fail-through enabled.

#### Requirements
- Docker: Up-to-date OpenSwitch docker image and two pre-configured openswitch/tacacs_server image
- Physical: AS5712 switch loaded with up-to-date OpenSwitch image, two TACACS+ servers loaded with pre-configured openswitch/tacacs_server image

#### Setup

##### Topology diagram
```ditaa
+----------+   +----------+   +----------+
|  Host 1  +---+  Switch  +---+  Host 1  |
+----------+   +----------+   +----------+
```

##### Test Setup

##### **TACACS+ server setup**
1. Disable TACACS+ service on two hosts
```
service tac_plus stop
```
2. Configure passkey(authentication key) on both host, passkey should show up in
   **/etc/tacacs/tac_plus.conf** as following:
```
key = "tac_test"
```
3. Create user user1 on host 1, user1 should show up in **/etc/tacacs/tac_plus.conf** as following:
```
  user = user_chap {
        chap = cleartext use_chap_passwd
        service = exec {
         priv-lvl = 14
        }
  }
```
4. Enable TACACS+ service on two hosts
```
service tac_plus start
```

##### Authentication client (OpenSwitch) setup
1. Get ip address of two hosts
2. Configure the switch as TACACS+ authentication client and add two TACACS+ hosts
```
configure terminal
tacacs-server key tac_test
tacacs-server host 172.17.0.2
tacacs-server host 172.17.0.3 key tac_test auth-type chap
aaa group server tacacs+ sg1
(config-sg) server 172.17.0.2
exit
aaa group server tacacs+ sg2
(config-sg) server 172.17.0.3
exit
aaa authentication login default group sg1 sg2
```
3. Enable fail-through option
```
configure terminal
aaa authentication allow-fail-through
```

#### Description
User should be able to pass TACACS+ server authentication and login to switch use username/password configured on secondary TACACS+ server with fail-through enabled

#### Test result criteria

##### Test pass criteria
User user_chap (password: user_chap_passwd) able to pass TACACS+ server authentication and login to OpenSwitch

##### Test fail criteria
User user_chap (password: user_chap_passwd) failed to login after three password attempts


### Local authentication first priority with fail-through

#### Objective
This test case validates if local user able to login to switch with local authentication (first priority) and fail-through enabled.

#### Requirements
- Docker: Up-to-date OpenSwitch docker image and two pre-configured openswitch/tacacs_server image
- Physical: AS5712 switch loaded with up-to-date OpenSwitch image, two TACACS+ servers loaded with pre-configured openswitch/tacacs_server image

#### Setup

##### Topology diagram
```ditaa
+----------+   +----------+   +----------+
|  Host 1  +---+  Switch  +---+  Host 1  |
+----------+   +----------+   +----------+
```

##### Test Setup

##### **TACACS+ server setup**
1. Disable TACACS+ service on two hosts
```
service tac_plus stop
```
2. Configure passkey(authentication key) on both host, passkey should show up in
   **/etc/tacacs/tac_plus.conf** as following:
```
key = "tac_test"
```
3. Enable TACACS+ service on two hosts
```
service tac_plus start
```

##### Authentication client (OpenSwitch) setup
1. Get ip address of two hosts
2. Configure the switch as authentication client and add two TACACS+ hosts
```
configure terminal
tacacs-server key tac_test
tacacs-server host 172.17.0.2
tacacs-server host 172.17.0.3 key tac_test auth-type chap
aaa group server tacacs+ sg1
(config-sg) server 172.17.0.2
exit
aaa group server tacacs+ sg2
(config-sg) server 172.17.0.3
exit
```
3. Configure group priority
```
aaa authentication login default group local sg1 sg2
```
4. Enable fail-through option
```
aaa authentication allow-fail-through
end
```

#### Description
User should be able to pass local authentication and login to switch use username/password configured on switch with fail-through enabled regardless local group priority

#### Test result criteria

##### Test pass criteria
Local user netop (password: netop) able to pass local authentication and login to OpenSwitch

##### Test fail criteria
User netop (password: netop) failed to login after three password attempts


### Local authentication second priority with fail-through

#### Objective
This test case validates if local user able to login to switch with local authentication (second priority) and fail-through enabled.

#### Requirements
- Docker: Up-to-date OpenSwitch docker image and two pre-configured openswitch/tacacs_server image
- Physical: AS5712 switch loaded with up-to-date OpenSwitch image, two TACACS+ servers loaded with pre-configured openswitch/tacacs_server image

#### Setup

##### Topology diagram
```ditaa
+----------+   +----------+   +----------+
|  Host 1  +---+  Switch  +---+  Host 1  |
+----------+   +----------+   +----------+
```

##### Test Setup

##### **TACACS+ server setup**
1. Disable TACACS+ service on two hosts
```
service tac_plus stop
```
2. Configure passkey(authentication key) on both host, passkey should show up in
   **/etc/tacacs/tac_plus.conf** as following:
```
key = "tac_test"
```
3. Enable TACACS+ service on two hosts
```
service tac_plus start
```

##### Authentication client (OpenSwitch) setup
1. Get ip address of two hosts
2. Configure the switch as authentication client and add two TACACS+ hosts
```
configure terminal
tacacs-server key tac_test
tacacs-server host 172.17.0.2
tacacs-server host 172.17.0.3 key tac_test auth-type chap
aaa group server tacacs+ sg1
(config-sg) server 172.17.0.2
exit
aaa group server tacacs+ sg2
(config-sg) server 172.17.0.3
exit
```
3. Configure group priority
```
aaa authentication login default group sg1 local sg2
```
4. Enable fail-through option
```
aaa authentication allow-fail-through
end
```

#### Description
User should be able to pass local authentication and login to switch use username/password configured on switch with fail-through enabled regardless local group priority

#### Test result criteria

##### Test pass criteria
Local user netop (password: netop) able to pass local authentication and login to OpenSwitch

##### Test fail criteria
User netop (password: netop) failed to login after three password attempts


### Local authentication last priority with fail-through

#### Objective
This test case validates if local user able to login to switch with local authentication (last priority) and fail-through enabled.

#### Requirements
- Docker: Up-to-date OpenSwitch docker image and two pre-configured openswitch/tacacs_server image
- Physical: AS5712 switch loaded with up-to-date OpenSwitch image, two TACACS+ servers loaded with pre-configured openswitch/tacacs_server image

#### Setup

##### Topology diagram
```ditaa
+----------+   +----------+   +----------+
|  Host 1  +---+  Switch  +---+  Host 1  |
+----------+   +----------+   +----------+
```

##### Test Setup

##### **TACACS+ server setup**
1. Disable TACACS+ service on two hosts
```
service tac_plus stop
```
2. Configure passkey(authentication key) on both host, passkey should show up in
   **/etc/tacacs/tac_plus.conf** as following:
```
key = "tac_test"
```
3. Enable TACACS+ service on two hosts
```
service tac_plus start
```

##### Authentication client (OpenSwitch) setup
1. Get ip address of two hosts
2. Configure the switch as authentication client and add two TACACS+ hosts
```
configure terminal
tacacs-server key tac_test
tacacs-server host 172.17.0.2
tacacs-server host 172.17.0.3 key tac_test auth-type chap
aaa group server tacacs+ sg1
(config-sg) server 172.17.0.2
exit
aaa group server tacacs+ sg2
(config-sg) server 172.17.0.3
exit
```
3. Configure group priority
```
aaa authentication login default group sg1 sg2 local
```
4. Enable fail-through option
```
aaa authentication allow-fail-through
end
```

#### Description
User should be able to pass local authentication and login to switch use username/password configured on switch with fail-through enabled regardless local group priority

#### Test result criteria

##### Test pass criteria
Local user netop (password: netop) able to pass local authentication and login to OpenSwitch

##### Test fail criteria
User netop (password: netop) failed to login after three password attempts

## Test no authentication option

### No authentication option user and password

#### Objective
This test case validates if user able to login to switch with correct username/password and authentication configuration removed (default: local)

#### Requirements
- Docker: Up-to-date OpenSwitch docker image and two pre-configured openswitch/tacacs_server image
- Physical: AS5712 switch loaded with up-to-date OpenSwitch image, two TACACS+ servers loaded with pre-configured openswitch/tacacs_server image

#### Setup

##### Topology diagram
```ditaa
+----------+   +----------+   +----------+
|  Host 1  +---+  Switch  +---+  Host 1  |
+----------+   +----------+   +----------+
```

##### Test Setup

##### **Authentication client (OpenSwitch) setup**
1. Add user netop (password: netop) to swith
2. Remove authentication configuration
```
configure terminal
no aaa authentication login default
```

#### Test result criteria

##### Test pass criteria
Local user netop (password: netop) able to pass local authentication and login to OpenSwitch

##### Test fail Criteria
Local user netop failed to login after provide password three times


### No authentication option user and incorrect password

#### Objective
This test case validates if user login fails with correct username/incorrect password and authentication configuration removed (default: local)

#### Requirements
- Docker: Up-to-date OpenSwitch docker image and two pre-configured openswitch/tacacs_server image
- Physical: AS5712 switch loaded with up-to-date OpenSwitch image, two TACACS+ servers loaded with pre-configured openswitch/tacacs_server image

#### Setup

##### Topology diagram
```ditaa
+----------+   +----------+   +----------+
|  Host 1  +---+  Switch  +---+  Host 1  |
+----------+   +----------+   +----------+
```
##### Test Setup

##### **Authentication client (OpenSwitch) setup**
1. Add user netop (password: netop) to swith
2. Remove authentication configuration
```
configure terminal
no aaa authentication login default
```

#### Test result criteria

##### Test pass criteria
Local user netop failed to login after provide password three times

##### Test fail criteria
Local user netop (password: dummy) able to pass local authentication and login to OpenSwitch


### No authentication option non-existent user

#### Objective
This test case validates if user login fails with non-existent user and authentication configuration removed

#### Requirements
- Docker: Up-to-date OpenSwitch docker image and two pre-configured openswitch/tacacs_server image
- Physical: AS5712 switch loaded with up-to-date OpenSwitch image, two TACACS+ servers loaded with pre-configured openswitch/tacacs_server image

#### Setup

##### Topology diagram
```ditaa
+----------+   +----------+   +----------+
|  Host 1  +---+  Switch  +---+  Host 1  |
+----------+   +----------+   +----------+
```
##### Test Setup

##### **Authentication client (OpenSwitch) setup**
1. Add user netop (password: netop) to swith
2. Remove authentication configuration
```
configure terminal
no aaa authentication login default
```

#### Test result criteria

##### Test pass criteria
Non-existent user dummy (password: dummypasswd) failed to login after provide password three times

##### Test fail criteria
Non-existent user dummy (password: dummypasswd) able to pass local authentication and login to OpenSwitch

## IPv6 test

### TACACS+ authentication IPv6 user login

#### Objective
This test case validates if user able to login to switch with correct username/password and TACACS+ server authentication enabled

#### Requirements
- Docker: Up-to-date OpenSwitch docker image and two pre-configured openswitch/tacacs_server image
- Physical: AS5712 switch loaded with up-to-date OpenSwitch image, two TACACS+ servers loaded with pre-configured openswitch/tacacs_server image

#### Setup

##### Topology diagram
```ditaa
+----------+   +----------+   +----------+
|  Host 1  +---+  Switch  +---+  Host 1  |
+----------+   +----------+   +----------+
```

##### Test Setup

##### **TACACS+ server setup**
1. Disable TACACS+ service on two hosts
```
service tac_plus stop
```
2. Configure passkey(authentication key) on both host, passkey should show up in
   **/etc/tacacs/tac_plus.conf** as following:
```
key = "tac_test"
```
3. Create user user1 on host 1, user1 should show up in **/etc/tacacs/tac_plus.conf** as following:
```
  user = user1 {
        pap = cleartext user1
        service = exec {
         priv-lvl = 14
        }
  }
```
4. Enable TACACS+ service on two hosts
```
service tac_plus start
```

##### Authentication client (OpenSwitch) setup
1. Get ipv6 address of two hosts
2. Configure the switch as TACACS+ authentication client and add two TACACS+ hosts
```
configure terminal
tacacs-server key tac_test
tacacs-server host 2013:cdba:1002:1304:4001:2005:3257:2000
tacacs-server host 2013:cdba:1002:1304:4001:2005:3257:3000 key tac_test auth-type chap
aaa group server tacacs+ sg1
(config-sg) server 2013:cdba:1002:1304:4001:2005:3257:2000
exit
aaa group server tacacs+ sg2
(config-sg) server 2013:cdba:1002:1304:4001:2005:3257:3000
exit
aaa authentication login default group sg1
```

#### Description
User should be able to pass TACACS+ server group authentication and login to switch use
username/password configured on primary TACACS+ server

#### Test result criteria

##### Test pass criteria
User user1 (password: user1) able to pass TACACS+ server authentication and login to OpenSwitch

##### Test fail criteria
User user1 (password: user1) failed to login after provide password three times

## Test source interface option

### Interface address as the source interface

#### Objective
This test case validates if the tacacs server can be reached through interface 1

#### Requirements
- Docker: Up-to-date OpenSwitch docker image and a pre-configured openswitch/tacacs_server image
- Physical: AS5712 switch loaded with up-to-date OpenSwitch image, a TACACS+ server loaded with pre-configured openswitch/tacacs_server image

#### Setup

##### Topology diagram
```ditaa
+----------+             +----------+             +----------+
|  Host 1  +-------------+  Switch  +-------------+ Host 2   |
+----------+       int 1 +----------+ OOBM        +----------+
```

##### Test Setup

##### **Authentication client (OpenSwitch) setup**
1. Configure interface 1 as the source interface for tacacs
```
configure terminal
ip source-interface tacacs <primary ip address of interface>
```

#### Test result criteria

##### Test pass criteria
Tacacs User be able to pass tacacs authentication and login to OpenSwitch

##### Test fail Criteria
Tacacs User failed to pass tacacs authentication and login to OpenSwitch

### Interface name as the source interface

#### Objective
This test case validates if the tacacs server can be reached through interface 1

#### Requirements
- Docker: Up-to-date OpenSwitch docker image and a pre-configured openswitch/tacacs_server image
- Physical: AS5712 switch loaded with up-to-date OpenSwitch image, a TACACS+ server loaded with pre-configured openswitch/tacacs_server image

#### Setup

##### Topology diagram
```ditaa
+----------+             +----------+             +----------+
|  Host 1  +-------------+  Switch  +-------------+ Host 2   |
+----------+       int 1 +----------+ OOBM        +----------+
```

##### Test Setup

##### **Authentication client (OpenSwitch) setup**
1. Configure interface 1 as the source interface for tacacs
```
configure terminal
ip source-interface tacacs interface 1
```

#### Test result criteria

##### Test pass criteria
Tacacs User be able to pass tacacs authentication and login to OpenSwitch

##### Test fail Criteria
Tacacs User failed to pass tacacs authentication and login to OpenSwitch

### Loopback address as the source interface

#### Objective
This test case validates if the tacacs server can be reached if loopback is used for the
source interface

#### Requirements
- Docker: Up-to-date OpenSwitch docker image and a pre-configured openswitch/tacacs_server image
- Physical: AS5712 switch loaded with up-to-date OpenSwitch image, a TACACS+ server loaded with pre-configured openswitch/tacacs_server image

#### Setup

##### Topology diagram
```ditaa
+----------+             +----------+             +----------+
|  Host 1  +-------------+  Switch  +-------------+ Host 2   |
+----------+       int 1 +----------+ OOBM        +----------+
```

##### Test Setup

##### **Authentication client (OpenSwitch) setup**
1. Configure loopback address as the source interface for tacacs
```
configure terminal
ip source-interface tacacs address <ip address of loopback>
```

#### Test result criteria

##### Test pass criteria
Tacacs User be able to pass tacacs authentication and login to OpenSwitch

##### Test fail Criteria
Tacacs User failed to pass tacacs authentication and login to OpenSwitch

### Loopback name as the source interface

#### Objective
This test case validates if the tacacs server can be reached if loopback interface is used
for the source interface

#### Requirements
- Docker: Up-to-date OpenSwitch docker image and a pre-configured openswitch/tacacs_server image
- Physical: AS5712 switch loaded with up-to-date OpenSwitch image, a TACACS+ server loaded with pre-configured openswitch/tacacs_server image

#### Setup

##### Topology diagram
```ditaa
+----------+             +----------+             +----------+
|  Host 1  +-------------+  Switch  +-------------+ Host 2   |
+----------+       int 1 +----------+ OOBM        +----------+
```

##### Test Setup

##### **Authentication client (OpenSwitch) setup**
1. Configure loopback interface as the source interface for tacacs
```
configure terminal
ip source-interface tacacs address loopback1
```

#### Test result criteria

##### Test pass criteria
Tacacs User be able to pass tacacs authentication and login to OpenSwitch

##### Test fail Criteria
Tacacs User failed to pass tacacs authentication and login to OpenSwitch

### OOBM address as the source interface

#### Objective
This test case validates if the tacacs server can be reached if OOBM address is used for
the source interface

#### Requirements
- Docker: Up-to-date OpenSwitch docker image and a pre-configured openswitch/tacacs_server image
- Physical: AS5712 switch loaded with up-to-date OpenSwitch image, a TACACS+ server loaded with pre-configured openswitch/tacacs_server image

#### Setup

##### Topology diagram
```ditaa
+----------+             +----------+             +----------+
|  Host 1  +-------------+  Switch  +-------------+ Host 2   |
+----------+       int 1 +----------+ OOBM        +----------+
```

##### Test Setup

##### **Authentication client (OpenSwitch) setup**
1. Configure OOBM address as the source interface for tacacs
```
configure terminal
ip source-interface tacacs address <ip address of OOBM port>
```

#### Test result criteria

##### Test pass criteria
Tacacs User be able to pass tacacs authentication and login to OpenSwitch

##### Test fail Criteria
Tacacs User failed to pass tacacs authentication and login to OpenSwitch

### No source interface configuration

#### Objective
This test case validates if the tacacs server can be reached if no source interface
configuration is present.  In this case, tacacs server should be reached through the
default OOBM port

#### Requirements
- Docker: Up-to-date OpenSwitch docker image and a pre-configured openswitch/tacacs_server image
- Physical: AS5712 switch loaded with up-to-date OpenSwitch image, a TACACS+ server loaded with pre-configured openswitch/tacacs_server image

#### Setup

##### Topology diagram
```ditaa
+----------+             +----------+             +----------+
|  Host 1  +-------------+  Switch  +-------------+ Host 2   |
+----------+       int 1 +----------+ OOBM        +----------+
```

##### Test Setup

##### **Authentication client (OpenSwitch) setup**
1. Remove the source interface configuration
```
configure terminal
no ip source-interface tacacs
```

#### Test result criteria

##### Test pass criteria
Tacacs User be able to pass tacacs authentication and login to OpenSwitch

##### Test fail Criteria
Tacacs User failed to pass tacacs authentication and login to OpenSwitch


## Test TACACS+ command authorization

### Set none as TACACS+ command authorization and test command authorization

#### Objective
This test case validates if command authorization works after configuring none for
authorizing a command for a perticular user.

#### Requirements
- Docker: Up-to-date OpenSwitch docker image and two pre-configured openswitch/tacacs_server image
- Physical: AS5712 switch loaded with up-to-date OpenSwitch image, two TACACS+ servers loaded with pre-configured openswitch/tacacs_server image

#### Setup

##### Topology diagram
```ditaa
+----------+   +----------+   +----------+
|  Host 1  +---+  Switch  +---+  Host 1  |
+----------+   +----------+   +----------+
```

##### Test Setup

##### **Authentication client (OpenSwitch) setup**
1. Configure none for tacacs cmd authorization

```
configure terminal
aaa authorization commands default none
```

#### Test result criteria

##### Test pass criteria
After authorization is configured, user should be able to run "show running-config" command

##### Test fail Criteria
After authorization is configured, user tries to run show running-config and receives
"Cannot execute command. Command not allowed" error message.


### Set TACACS+ groups and none as tacacs cmd authorization and test command authorization

#### Objective
This test case validates if command authorization works after configuring tacacs
server for the authorizing a command for a perticular user.

#### Requirements
- Docker: Up-to-date OpenSwitch docker image and two pre-configured openswitch/tacacs_server image
- Physical: AS5712 switch loaded with up-to-date OpenSwitch image, two TACACS+ servers loaded with pre-configured openswitch/tacacs_server image

#### Setup

##### Topology diagram
```ditaa
+----------+   +----------+   +----------+
|  Host 1  +---+  Switch  +---+  Host 1  |
+----------+   +----------+   +----------+
```

##### Test Setup

##### **Authentication client (OpenSwitch) setup**
1. Configure tacacs servers
2. add tacacs servers  to groups
3. enable aaa tacacs authorization
```
configure terminal
tacacs-server host 192.168.1.254 key tac_test
tacacs-server host 192.168.1.253 key_tac_test
aaa group server tacacs_plus tac1
server 192.168.1.254
exit
aaa group server tacacs_plus tac2
server 192.168.1.253
exit
aaa authorization commands default group tac1 tac2 none
```
#### Test result criteria

##### Test pass criteria
After authorization is configured, user should be able to run "show running-config" command

##### Test fail Criteria
After authorization is configured, user tries to run show running-config and receives
"Cannot execute command. Command not allowed" error message.


### SSH to switch as a remote TACACS+ user and test command authorization

#### Objective
This test case validates if an authenticated user withour command authoirization
privilege can execute commands

#### Requirements
- Docker: Up-to-date OpenSwitch docker image and two pre-configured openswitch/tacacs_server image
- Physical: AS5712 switch loaded with up-to-date OpenSwitch image, two TACACS+ servers loaded with pre-configured openswitch/tacacs_server image

#### Setup

##### Topology diagram
```ditaa
+----------+   +----------+   +----------+
|  Host 1  +---+  Switch  +---+  Host 1  |
+----------+   +----------+   +----------+
```

##### Test Setup

##### **Authentication client (OpenSwitch) setup**
1. set tacacs servers and tacacs command authorization
1. setup tacacs authentiation
2. ssh from host to switch with tacacs authentication
```
configure terminal
tacacs-server host 192.168.1.254 key tac_test
tacacs-server host 192.168.1.253 key_tac_test
aaa group server tacacs_plus tac1
server 192.168.1.254
exit
aaa group server tacacs_plus tac2
server 192.168.1.253
exit
aaa authorization commands default group tac1 tac2 none
aaa authentication login default group tac2 local
```

#### Test result criteria

##### Test pass criteria
After user is authenticated and authorization is configured, user should not be able to run "show running-config" command
User should expect "Cannot execute command. Command not allowed"

##### Test fail Criteria
User is able to execute commands without an issue.


### Set unreachable TACACS+ server for TACACS+ cmd authorization and test cmd authorization

#### Objective
This test case validates if tacacs servers are unreachable, user should not be able to
execute any command.

#### Requirements
- Docker: Up-to-date OpenSwitch docker image and two pre-configured openswitch/tacacs_server image
- Physical: AS5712 switch loaded with up-to-date OpenSwitch image, two TACACS+ servers loaded with pre-configured openswitch/tacacs_server image

#### Setup

##### Topology diagram
```ditaa
+----------+   +----------+   +----------+
|  Host 1  +---+  Switch  +---+  Host 1  |
+----------+   +----------+   +----------+
```

##### Test Setup

##### **Authentication client (OpenSwitch) setup**
1. set tacacs servers and tacacs command authorization
```
configure terminal
tacacs-server host 1.1.1.1
aaa group server tacacs_plus tac3
server 1.1.1.1
exit
aaa authorization commands default group tac3
```

#### Test result criteria

##### Test pass criteria
User should not be able to execute any command and receives,
"Cannot execute command. Could not connect to any TACACS+ servers" as an error.

##### Test fail Criteria
User is able to execute commands without an issue.
