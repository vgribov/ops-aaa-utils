#!/usr/bin/env python
# Copyright (C) 2015-2016 Hewlett Packard Enterprise Development LP
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.
# =======================================================
# Module: cookiesecret.py
# Description: functions to manage cookie secret value
# =======================================================

import OpenSSL
import os

# =======================================================
# Function: generate_cookie_secret.py
# Description: generate value to be used as cookie secret
#              By default set_secure_cookie uses HMAC-SHA-
#              256.
# =======================================================


def generate_cookie_secret():
    SECURE_COOKIE_LEN = 256 / 8
    cookie_secret_file_path = "/var/run/persistant_cookie_secret"
    if os.path.isfile(cookie_secret_file_path):
        with open(cookie_secret_file_path, 'r') as cookie_secret_file:
            string2 = cookie_secret_file.read()
    else:
        string1 = os.urandom(SECURE_COOKIE_LEN)
        OpenSSL.rand.seed(string1)
        string2 = OpenSSL.rand.bytes(SECURE_COOKIE_LEN)
        with open(cookie_secret_file_path, 'w+') as cookie_secret_file:
            cookie_secret_file.write(string2)
        os.chmod(cookie_secret_file_path, 0600)
    return string2
