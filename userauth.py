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

import tornado.web
import PAM
import pwd

val = ''

# ============================================================
# Cookie expiration time, represent by day(s)
# Example:
#  Set EXPIRES_DAYS to 0.07 to instruct browser discard cookie
#  after approximately 1 hour 40 minutes
#
#  (Optional) Set MAX_AGE_DAYS as oldest cookie that server
#   will accept, which is approximately 1 hour 55 minutes
#   notice MAX_AGE_DAYS should be larger than EXPIRES_DAYS
# ============================================================
MAX_AGE_DAYS = 0.08
EXPIRES_DAYS = 0.07


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
    username = get_request_user(request)
    if username and _user_exists(username):
        return True
    else:
        return False


def get_request_user(request):
    '''
    The request argument is an instance of class tornado.web.RequestHandler.
    Function determines the authenticated user using the cookie contained
    in the request.
    Returns the authenticated user or None is not authenticated
    '''
    return request.get_secure_cookie("user", max_age_days=MAX_AGE_DAYS)


def _pam_conv(auth, query_list, userData):
    '''
    This is not a public api.
    '''
    global val
    resp = []
    resp.append((val, 0))
    return resp


def _user_exists(username):
    try:
        return pwd.getpwnam(username) is not None
    except KeyError:
        return False


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
        request.set_secure_cookie("user",
                                  request.get_argument("username"),
                                  expires_days=EXPIRES_DAYS)
        return True
