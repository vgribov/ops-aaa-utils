# RADIUS Test Cases

## Contents
- [Test addition of RADIUS server (with no optional parameters)](#test-addition-of-radius-server-with-no-optional-parameters)
- [Test addition of RADIUS server (with key option)](#test-addition-of-radius-server-with-key-option)
- [Test addition of RADIUS server (with timeout option)](#test-addition-of-radius-server-with-timeout-option)
- [Test addition of RADIUS server (with port option)](#test-addition-of-radius-server-with-port-option)
- [Test addition of RADIUS server (with auth-type option)](#test-addition-of-radius-server-with-auth-type-option)
- [Test addition of RADIUS server (with all valid options)](#test-addition-of-radius-server-with-all-valid-options)
- [Test addition of RADIUS server (with IPv6 and all valid options)](#test-addition-of-radius-server-with-ipv6-and-all-valid-options)
- [Test addition failure of server with invalid server name](#test-addition-failure-of-server-with-invalid-server-name)
- [Test addition failure of RADIUS server (with invalid key option)](#test-addition-failure-of-radius-server-with-invalid-key-option)
- [Test addition failure of RADIUS server (with invalid timeout option)](#test-addition-failure-of-radius-server-with-invalid-timeout-option)
- [Test addition failure of RADIUS server (with invalid port option)](#test-addition-failure-of-radius-server-with-invalid-port-option)
- [Test addition of RADIUS server (with retries option)](#test-addition-of-radius-server-with-retries-option)
- [Test addition failure of RADIUS server (with invalid retries option)](#test-addition-failure-of-radius-server-with-invalid-retries-option)
- [Test addition of RADIUS global config](#test-addition-of-radius-global-config)
- [Test addition of server with valid FQDN](#test-addition-of-server-with-valid-FQDN)
- [Test deletion of RADIUS server](#test-deletion-of-radius-server)
- [Test addition of more than 64 RADIUS servers](#test-addition-of-more-than-64-radius-servers)
- [Test modification of 64th RADIUS server](#test-modification-of-64th-radius-server)
- [Test creation of RADIUS server group](#test-creation-of-radius-server-group)
- [Test addition of server to RADIUS server group](#test-addition-of-server-to-radius-server-group)
- [Test assignment of previously assigned RADIUS server to a new server group](#test-assigment-of-previously-assigned-radius-server-to-a-new-server-group)
- [Test deletion of server from RADIUS server group](#test-deletion-of-server-from-radius-server-group)
- [Test deletion of RADIUS server group](#test-deletion-of-radius-server-group)

## Test addition of RADIUS server (with no optional parameters)
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
- Add a RADIUS server using just the IPV4 address.
- Add a RADIUS server using just the FQDN.

### Test result criteria
#### Test pass criteria
The two RADIUS servers are present in the `show radius-server detail` command output.
#### Test Fail Criteria
The two RADIUS servers are absent from the `show radius-server detail` command output.

## Test addition of RADIUS server (with key option)
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
Add a RADIUS server using an IPv4 address and the key option.

### Test result criteria
#### Test pass criteria
This server is present in the `show radius-server detail` command output.
#### Test fail criteria
This server is absent from the `show radius-server detail` command output.

## Test addition of RADIUS server (with timeout option)
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
Add a RADIUS server using an IPv4 address and the timeout option.

### Test result criteria
#### Test pass criteria
This server is present in the `show radius-server detail` command output.
#### Test fail criteria
This server is absent from the `show radius-server detail` command output.

## Test addition of RADIUS server (with port option)
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
Add a RADIUS server using an IPv4 address and the port option.

### Test result criteria
#### Test pass criteria
This server is present in the `show radius-server detail` command output.
#### Test fail criteria
This server is absent from the `show radius-server detail` command output.

## Test addition of RADIUS server (with auth-type option)
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
Add a RADIUS server using an IPv4 address and the auth-type option.

### Test result criteria
#### Test pass criteria
This server is present in the `show radius-server detail` command output.
#### Test fail criteria
This server is absent from the `show radius-server detail` command output.

## Test addition of RADIUS server (with all valid options)
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
Add a RADIUS server using an IPv4 address and all options with valid values.

### Test result criteria
#### Test pass criteria
This server is present in the `show radius-server detail` command output.
#### Test fail criteria
This server is absent from the `show radius-server detail` command output.

## Test addition of RADIUS server (with IPv6 and all valid options)
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
Add a RADIUS server using an IPv6 address and all options with valid values.

### Test result criteria
#### Test pass criteria
This server is present in the `show radius-server detail` command output.
#### Test fail criteria
This server is absent from the `show radius-server detail` command output.

## Test addition failure of RADIUS server with invalid server name
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
Add a RADIUS server using an ill-formatted IPv4 address.

### Test result criteria
#### Test pass criteria
This server is absent from the `show radius-server detail` command output.
#### Test Fail Criteria
This server is present in the `show radius-server detail` command output.

## Test addition failure of RADIUS server (with invalid key option)
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
Add the RADIUS server using the IPV4 address and invalid key value.

### Test result criteria
#### Test pass criteria
This server is absent from the `show radius-server detail` command output.
#### Test Fail Criteria
This server is present in the `show radius-server detail` command output and displays the specified key.

## Test addition failure of RADIUS server (with invalid timeout option)
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
Add the RADIUS server using the IPV4 address and invalid timeout value.

### Test result criteria
#### Test pass criteria
This server is absent from the `show radius-server detail` command output.
#### Test Fail Criteria
This server is present in the `show radius-server detail` command output and displays the specified timeout.

## Test addition failure of RADIUS server (with invalid port option)
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
Add the RADIUS server using the IPV4 address and invalid port value.

### Test result criteria
#### Test pass criteria
This server is absent from the `show radius-server detail` command output.
#### Test Fail Criteria
This server is present in the `show radius-server detail` command output and displays the specified port.

## Test addition of RADIUS server (with retries option)
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
Add a RADIUS server using an IPv4 address and the retries option.

### Test result criteria
#### Test pass criteria
This server is present in the `show radius-server detail` command output.
#### Test fail criteria
This server is absent from the `show radius-server detail` command output.

## Test addition failure of RADIUS server (with invalid retries option)
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
Add the RADIUS server using the IPV4 address and invalid retries value.

### Test result criteria
#### Test pass criteria
This server is absent from the `show radius-server detail` command output.
#### Test Fail Criteria
This server is present in the `show radius-server detail` command output and displays the specified retries.

## Test addition of RADIUS global config
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
Add global key, port, retries and timeout values

### Test result criteria
#### Test pass criteria
The global values are present in `show radius-server detail` command output.
#### Test Fail Criteria
This global values are absent in the `show radius-server detail` command output.

## Test addition of server with valid FQDN
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
- Add a RADIUS server with a FQDN.

### Test result criteria
#### Test pass criteria
The server is present in the `show radius-server detail` command output.
#### Test Fail Criteria
The server is absent from the `show radius-server detail` command output.

## Test deletion of RADIUS server
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
- Delete a RADIUS server with IP/FQDN.

### Test result criteria
#### Test pass criteria
This server is absent from the `show radius-server detail` command output.
#### Test Fail Criteria
This server is present in the `show radius-server detail` command output.

## Test addition of more than 64 RADIUS servers
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
- Add more than 64 RADIUS servers.

### Test result criteria
#### Test pass criteria
An error message telling user that maximum allowed RADIUS servers have been configured.
#### Test Fail Criteria
A 65th RADIUS server is added, or the error message is not displayed.

## Test modification of 64th RADIUS server
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
- Add 64 RADIUS servers.
- Modify the timeout for the 64th RADIUS server.

### Test result criteria
#### Test pass criteria
Modified timeout value for RADIUS server under consideration is reflected in `show radius-server detail`.
#### Test Fail Criteria
If the updated timeout is not correctly reflected then the test would fail.

## Test creation of RADIUS server group
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
- Create two RADIUS server group sg1 sg2

### Test result criteria
#### Test pass criteria
The two newly created RADIUS server groups are present in `show running-config` comand output.
#### Test Fail Criteria
The two RADIUS server groups are absent from the `show running-config` command output.

## Test addition of server to RADIUS server group
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
- Assign four previously created RADIUS servers to RADIUS server group sg1

### Test result criteria
#### Test pass criteria
The four RADIUS servers present in server group table as newly assigned sg1 group member in `show aaa server-group` command output.
#### Test Fail Criteria
The four RADIUS servers present in server group table as default radius group member in the `show aaa server-group` command output.

## Test assigment of previously assigned RADIUS server to a new server group
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
- Assign RADIUS server group sg1 group member to server group sg2

### Test result criteria
#### Test pass criteria
Error message `RADIUS server already assigned to a group!` returned.
The RADIUS server present in server group table as member of its original group sg1 in `show aaa server-group` command output.
#### Test Fail Criteria
The RADIUS server present in server group table as newly assigned sg2 group member in `show aaa server-group` command output.

## Test deletion of server from RADIUS server group
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
- Remove a previously assigned RADIUS server from its server group

### Test result criteria
#### Test pass criteria
The removed RADIUS server present in server group table as default radius group member in `show aaa server-group` command output.
#### Test Fail Criteria
The removed RADIUS server present in server group table as member of its original group in `show aaa server-group` command output.

## Test deletion of RADIUS server group
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
- Remove RADIUS server group sg1

### Test result criteria
#### Test pass criteria
The removed RADIUS server group sg1 is absent from the `show running-config` command output.
The group member of removed RADIUS server group sg1 present in server group table as default radius group member in `show aaa server-group` command output.
#### Test Fail Criteria
The removed RADIUS server group sg1 present in the `show running-config` command output.
The group member of removed RADIUS server group sg1 present in server group table as member of sg1 group in `show aaa server-group` command output.
