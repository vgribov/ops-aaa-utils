#!/usr/bin/env python
# Copyright (C) 2014-2015 Hewlett-Packard Development Company, L.P.
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import os
import sys

#Get file name from commandline argument
radiusTextToSearch = "pam_unix.so"
radiusTextToReplace = "pam_radius.so"

passwdTextToSearch = "pam_radius.so"
passwdTextToReplace = "pam_unix.so"

# Hardcoded file path
filename = ["/etc/pam.d/common-auth-halon","/etc/pam.d/common-account-halon","/etc/pam.d/common-password-halon","/etc/pam.d/common-session-halon"]

# Count Max value is No. of files present in filename
count = 0

#  Initialize file descriptor to 0, total fd is equal to number of filename's
fd = [0,0,0,0]

for count in range(0,4):
    fd[count] = open(filename[count],'r+')
    newdata = fd[count].read()
    fd[count].close()
    if len(sys.argv) == 1:
        print "Error: **enter argument radius/passwd**"
        break
    if sys.argv[1] == "radius":
        newdata = newdata.replace(radiusTextToSearch,radiusTextToReplace)
    elif sys.argv[1] == "passwd":
        newdata = newdata.replace(passwdTextToSearch,passwdTextToReplace)
    #else:
        #do nothing

    fd[count] = open(filename[count],'w')
    fd[count].write(newdata)
    fd[count].close()
    count += 1
