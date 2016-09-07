
# TACACS+ Test Cases

## Contents
- [Test addition of TACACS+ server (with no optional parameters)](#test-addition-of-tacacs-server-with-no-optional-parameters)
- [Test addition of TACACS+ server (with timeout option)](#test-addition-of-tacacs-server-with-timeout-option)
- [Test addition of TACACS+ server (with key option)](#test-addition-of-tacacs-server-with-key-option)
- [Test addition of TACACS+ server (with port option)](#test-addition-of-tacacs-server-with-port-option)
- [Test addition of TACACS+ server (with all valid options)](#test-addition-of-tacacs-server-with-all-valid-options)
- [Test addition failure of server with invalid server name](#test-addition-failure-of-server-with-invalid-server-name)
- [Test addition failure of TACACS+ server (with invalid timeout option)](#test-addition-failure-of-tacacs-server-with-invalid-timeout-option)
- [Test addition failure of TACACS+ server (with invalid port option)](#test-addition-failure-of-tacacs-server-with-invalid-port-option)
- [Test addition failure of TACACS+ server (with invalid key option)](#test-addition-failure-of-tacacs-server-with-invalid-key-option)
- [Test addition of TACACS+ server (with long server name)](#test-addition-of-tacacs-server-with-long-server-name)
- [Test addition of TACACS+ global config](#test-addition-of-tacacs-global-config)
- [Test addition of server with valid FQDN](#test-addition-of-server-with-valid-FQDN)
- [Test deletion of TACACS+ server](#test-deletion-of-tacacs-server)
- [Test addition of more than 64 TACACS+ servers](#test-addition-of-more-than-64-tacacs-servers)
- [Test modification of 64th TACACS+ server](#test-modification-of-64th-tacacs-server)

## Test addition of TACACS+ server (with no optional parameters)
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
- Add a TACACS+ server using just the IPV4 address.
- Add a TACACS+ server using just the FQDN.

### Test result criteria
#### Test pass criteria
The two TACACS+ servers are present in the `show tacacs-server detail` command output.
#### Test Fail Criteria
The two TACACS+ servers are absent from the `show tacacs-server detail` command output.

## Test addition of TACACS+ server (with timeout option)
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
Add a TACACS+ server using an IPv4 address and the timeout option.

### Test result criteria
#### Test pass criteria
This server is present in the `show tacacs-server detail` command output.
#### Test fail criteria
This server is absent from the `show tacacs-server detail` command output.

## Test addition of TACACS+ server (with key option)
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
Add a TACACS+ server using an IPv4 address and the key option.

### Test result criteria
#### Test pass criteria
This server is present in the `show tacacs-server detail` command output.
#### Test fail criteria
This server is absent from the `show tacacs-server detail` command output.

## Test addition of TACACS+ server (with port option)
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
Add a TACACS+ server using an IPv4 address and the port option.

### Test result criteria
#### Test pass criteria
This server is present in the `show tacacs-server detail` command output.
#### Test fail criteria
This server is absent from the `show tacacs-server detail` command output.

## Test addition of TACACS+ server (with auth-type option)
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
Add a TACACS+ server using an IPv4 address and the auth-type option.

### Test result criteria
#### Test pass criteria
This server is present in the `show tacacs-server detail` command output.
#### Test fail criteria
This server is absent from the `show tacacs-server detail` command output.

## Test addition of TACACS+ server (with all valid options)
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
Add a TACACS+ server using an IPv4 address and all options with valid values. 

### Test result criteria
#### Test pass criteria
This server is present in the `show tacacs-server detail` command output.
#### Test fail criteria
This server is absent from the `show tacacs-server detail` command output.

## Test addition of TACACS+ server (with all valid options, IPv6 as server name)
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
Add a TACACS+ server using an IPv6 address and all options with valid values.

### Test result criteria
#### Test pass criteria
This server is present in the `show tacacs-server detail` command output.
#### Test fail criteria
This server is absent from the `show tacacs-server detail` command output.

## Test addition failure of TACACS+ server with invalid server name
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
Add a TACACS+ server using an ill-formatted IPv4 address.

### Test result criteria
#### Test pass criteria
This server is absent from the `show tacacs-server detail` command output.
#### Test Fail Criteria
This server is present in the `show tacacs-server detail` command output.

## Test addition failure of TACACS+ server (with invalid timeout option)
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
Add the TACACS+ server using the IPV4 address and invalid timeout value. 

### Test result criteria
#### Test pass criteria
This server is absent from the `show tacacs-server detail` command output.
#### Test Fail Criteria
This server is present in the `show tacacs-server detail` command output and displays the specified timeout.

## Test addition failure of TACACS+ server (with invalid key option)
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
Add the TACACS+ server using the IPV4 address and invalid key value. 

### Test result criteria
#### Test pass criteria
This server is absent from the `show tacacs-server detail` command output.
#### Test Fail Criteria
This server is present in the `show tacacs-server detail` command output and displays the specified key.

## Test addition failure of TACACS+ server (with invalid port option)
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
Add the TACACS+ server using the IPV4 address and invalid port value. 

### Test result criteria
#### Test pass criteria
This server is absent from the `show tacacs-server detail` command output.
#### Test Fail Criteria
This server is present in the `show tacacs-server detail` command output and displays the specified port.

## Test addition of TACACS+ server (with long server name)
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
Add a TACACS+ using a long server name (exceed maximum length 45).

### Test result criteria
#### Test pass criteria
The server is present in the `show tacacs-server detail` command output.
#### Test Fail Criteria
The server is absent from the `show tacacs-server detail` command output.

## Test addition of TACACS+ global config
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
Add global key, port and timeout values 

### Test result criteria
#### Test pass criteria
The global values are present in `show tacacs-server detail` command output. 
#### Test Fail Criteria
This global values are absent in the `show tacacs-server detail` command output.

## Test addition of server with valid FQDN
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
- Add a TACACS+ server with a FQDN.

### Test result criteria
#### Test pass criteria
The server is present in the `show tacacs-server detail` command output.
#### Test Fail Criteria
The server is absent from the `show tacacs-server detail` command output.

## Test deletion of TACACS+ server
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
- Delete a TACACS+ server with IP/FQDN. 

### Test result criteria
#### Test pass criteria
This server is absent from the `show tacacs-server detail` command output.
#### Test Fail Criteria
This server is present in the `show tacacs-server detail` command output.

## Test addition of more than 64 TACACS+ servers
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
- Add more than 64 TACACS+ servers.

### Test result criteria
#### Test pass criteria
An error message telling user that maximum allowed TACACS+ servers have been configured. 
#### Test Fail Criteria
A 65th TACACS+ server is added, or the error message is not displayed. 

## Test modification of 64th TACACS+ server
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
- Add 64 TACACS+ servers.
- Modify the timeout for the 64th TACACS+ server.

### Test result criteria
#### Test pass criteria
Modified timeout value for TACACS+ server under consideration is reflected in `show tacacs-server detail`.
#### Test Fail Criteria
If the updated timeout is not correctly reflected then the test would fail.

## Test creation of TACACS+ server group
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
- Create two TACACS+ server group sg1 sg2

### Test result criteria
#### Test pass criteria
The two newly created TACACS+ server groups are present in `show running-config` comand output.
#### Test Fail Criteria
The two TACACS+ server groups are absent from the `show running-config` command output.

## Test assigment of TACACS+ server to server group
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
- Assign four previously created TACACS+ servers to TACACS+ server group sg1

### Test result criteria
#### Test pass criteria
The four TACACS+ servers present in server group table as newly assigned sg1 group member in `show aaa server-group` comand output.
#### Test Fail Criteria
The four TACACS+ servers present in server group table as default tacacs_plus group memmber in the `show aaa server-group` command output.

## Test assigment of previously assigned TACACS+ server to a new server group
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
- Assign TACACS+ server group sg1 group member to server group sg2

### Test result criteria
#### Test pass criteria
Error message `TACACS+ server already assigned to a group!` returned.
The TACACS+ server present in server group table as mebmber of its original group sg1 in `show aaa server-group` comand output.

#### Test Fail Criteria
The TACACS+ server present in server group table as newly assigned sg2 group member in `show aaa server-group` comand output.

## Test removal of TACACS+ server from TACACS+ server group
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
- Remove a previously assigned TACACS+ server from its server group

### Test result criteria
#### Test pass criteria
The removed TACACS+ server present in server group table as default tacacs_plus group member in `show aaa server-group` comand output.

#### Test Fail Criteria
The removed TACACS+ server present in server group table as member of its original group in `show aaa server-group` command output

## Test removal of TACACS+ server group
### Setup
#### Topology diagram
```ditaa
[s1]
```
### Description
- Remove TACACS+ server group sg1

### Test result criteria
#### Test pass criteria
The removed TACACS+ server group sg1 is absent from the `show running-config` command output.
The group member of removed TACACS+ server group sg1 present in server group table as default tacacs_plus group member in `show aaa server-group` comand output.

#### Test Fail Criteria
The removed TACACS+ server group sg1 present in the `show running-config` command output.
The group member of removed TACACS+ server group sg1 present in server group table as member of sg1 group in `show aaa server-group` comand output.
