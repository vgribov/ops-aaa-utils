#!/usr/bin/env python
# Copyright (C) 2015 Hewlett Packard Enterprise Development LP
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

import tornado.web
import PAM

val = ''

# =======================================================
# Module: userauth.py
# Description: Provides API's to REST user authentication
# =======================================================


def is_user_authenticated(request):
    '''
    The request argument is an instance of class tornado.web.RequestHandler.
    Function determines if the user generating the request is authenticated
    or not based the validation of the cookie contained in the request.
    Returns True if validation succeeds else False.
    '''
    if not request.get_secure_cookie("user"):
        return False
    else:
        return True


def _pam_conv(auth, query_list, userData):
    '''
    This is not a public api.
    '''
    global val
    resp = []
    resp.append((val, 0))
    return resp

# =============================================
# Example usage of handle_user_login
# ......
# ......
# ......
# if (userauth.handle_user_login(self) == True):
#      self.redirect("/")
#  else:
#       self.redirect("/login")
#
# application = tornado.web.Application([
#        (r"/", Main),
#        (r"/login", Login),
# ......
# ......
# ......
# =============================================


def handle_user_login(request):
    '''
    The request argument is an instance of class tornado.web.RequestHandler.
    This function authenticates the username and password contained in the
    request.
    The request is expected to contain values for "username" and "password".
    This function returns True if the authentication succeeds else returns
    False.
    '''
    global val

    service = 'rest'
    auth = PAM.pam()
    auth.start(service)
    user = request.get_argument("username")
    val = request.get_argument("password")
    auth.set_item(PAM.PAM_USER, user)
    auth.set_item(PAM.PAM_CONV, _pam_conv)
    try:
        auth.authenticate()
    except:
        return False
    else:
        request.set_secure_cookie("user", request.get_argument("username"))
        return True
