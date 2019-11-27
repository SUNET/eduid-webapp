# -*- coding: utf-8 -*-
#
# Copyright (c) 2019 SUNET
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

from typing import cast
from flask import current_app

from eduid_common.api.app import get_app_config
from eduid_common.api import mail_relay
from eduid_common.api import am, msg
from eduid_common.authn.middleware import AuthnApp
from eduid_webapp.{{cookiecutter.directory_name}}.settings.common import {{cookiecutter.class_name}}Config

__author__ = '{{cookiecutter.author}}'


class {{cookiecutter.class_name}}App(AuthnApp):

    def __init__(self, name, config):
        # Init config for common setup
        config = get_app_config(name, config)
        super({{cookiecutter.class_name}}App, self).__init__(name, config)
        # Init app config
        self.config = {{cookiecutter.class_name}}Config(**config)
        # Init dbs
        self.private_userdb = {{cookiecutter.class_name}}UserDB(self.config.mongo_uri)
        # Init celery
        msg.init_relay(self)
        am.init_relay(self, 'eduid_{{cookiecutter.directory_name}}')
        # Initiate external modules


def get_current_app() -> {{cookiecutter.class_name}}App:
    """Teach pycharm about {{cookiecutter.class_name}}App"""
    return current_app  # type: ignore


current_{{cookiecutter.directory_name}}_app = get_current_app()


def init_{{cookiecutter.directory_name}}_app(name: str, config: dict) -> {{cookiecutter.class_name}}App:
    """
    :param name: The name of the instance, it will affect the configuration loaded.
    :param config: any additional configuration settings. Specially useful
                   in test cases

    :return: the flask app
    """
    app = {{cookiecutter.class_name}}App(name, config)

    # Register views
    from eduid_webapp.{{cookiecutter.directory_name}}.views import {{cookiecutter.directory_name}}_views
    app.register_blueprint({{cookiecutter.directory_name}}_views, url_prefix=app.config.application_root)

    app.logger.info('{!s} initialized'.format(name))
    return app
