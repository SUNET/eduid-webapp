# -*- coding: utf-8 -*-
#
# Copyright (c) 2016 NORDUnet A/S
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
from typing import Dict

from eduid_common.config.base import EduIDBaseAppConfig


class JSConfigConfig(EduIDBaseAppConfig):
    """
    Configuration for the jsconfig app
    """

    app_name: str = 'jsconfig'

    eduid_static_url: str

    dashboard_bundle_path: str = 'front-build/dashboard-bundle.dev.js'
    dashboard_bundle_version: str = 'dev'
    # Dashboard feature toggle settings
    dashboard_bundle_feature_cookie: str = ''
    dashboard_bundle_feature_version: Dict[str, str] = {}
    # Signup config
    signup_bundle_path: str = 'front-build/signup-bundle.dev.js'
    signup_bundle_version: str = 'dev'
    tou_url: str = '/get-tous'
    # Signup feature toggle settings
    signup_bundle_feature_cookie: str = ''
    signup_bundle_feature_version: Dict[str, str] = {}
    # Login config
    login_bundle_path: str = 'front-build/login-bundle.dev.js'
    login_bundle_version: str = 'dev'
    # reset password config
    password_entropy: int = 25
    password_length: int = 12
    # Login feature toggle settings
    login_bundle_feature_cookie: str = ''
    login_bundle_feature_version: Dict[str, str] = {}

    mongo_uri: str = 'mongo_uri_not_used_in_jsconfig'
