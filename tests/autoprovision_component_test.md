#Autoprovision component test cases
## Contents##
- [Verify autoprovision functionality](#verify-autoprovision-functionality)
- [Check to ensure that autoprovision executes only once](#check-to-ensure-that-autoprovision-executes-only-once)


## Test cases to verify autoprovision utility ##
### Objective ###
Verify that the autoprovision utility downloads the script from the http server and executes it.

### Requirements ###
This test requires an AS5712 switch.

### Setup ###
#### Topology Diagram ####

                        +---------------------------------+
                        |                +---------------+|
                        |                |Lighttpd server||
                        |                | (Http server) ||
                        |                +---------------+|
                        |                                 |
                        |   AS5712 Switch                 |
                        |                                 |
                        |                                 |
                        +---------------------------------+

#### Test Setup ####
Set up an http server and create a hello world shell script in the http server page's root path.

### Verify autoprovision functionality###
#### Description ###
Verify that the autoprovision utility downloads the script and executes it from the URL passed as a parameter.

### Test Result Criteria ###
#### Test Pass Criteria ####
This test is successful if "show autoprovision" displays the autoprovision status as "yes" and if the URL is updated in the OVSDB.

#### Test Fail Criteria ####
This test fails if "show autoprovision" displays the autoprovision status as "no".

### Check to ensure that autoprovision executes only once###
#### Description ###
Confirm that the autoprovision utility does not execute if autoprovision is already executed. Execute the autoprovision utility again in the same setup where autoprovision was performed.

### Test Result Criteria ###
#### Test Pass Criteria ####
This test is successful if the "Autoprovisioning already completed" message is displayed.

#### Test Fail Criteria ####
This test fails if the "Autoprovisioning already completed" message is not displayed.
