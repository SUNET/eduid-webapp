# -*- coding: utf-8 -*-
#
# Copyright (c) 2016 NORDUnet A/S
# Copyright (c) 2020 SUNET
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
from typing import Any, Mapping, Optional, cast

from flask import current_app

from eduid_common.api import am, mail_relay, translation
from eduid_common.api.am import AmRelay
from eduid_common.api.mail_relay import MailRelay
from eduid_common.authn.middleware import AuthnBaseApp
from eduid_common.config.base import FlaskConfig
from eduid_common.config.parsers import load_config
from eduid_userdb.logs import ProofingLog
from eduid_userdb.proofing import EmailProofingStateDB, EmailProofingUserDB

from eduid_webapp.email.settings.common import EmailConfig


class EmailApp(AuthnBaseApp):
    def __init__(self, config: EmailConfig, **kwargs):
        self.conf = config
        super().__init__(config, **kwargs)

        self.am_relay = AmRelay(config.celery, 'eduid_email')
        self.mail_relay = MailRelay(config.celery)
        translation.init_babel(self)

        self.private_userdb = EmailProofingUserDB(self.conf.mongo_uri)
        self.proofing_statedb = EmailProofingStateDB(self.conf.mongo_uri)
        self.proofing_log = ProofingLog(self.conf.mongo_uri)


current_email_app: EmailApp = cast(EmailApp, current_app)


def email_init_app(name: str, test_config: Optional[Mapping[str, Any]]) -> EmailApp:
    """
    Create an instance of an eduid email app.

    :param name: The name of the instance, it will affect the configuration loaded.
    :param test_config: Override config, used in test cases.
    """

    config = load_config(typ=EmailConfig, app_name=name, ns='webapp', test_config=test_config)

    app = EmailApp(config)

    app.logger.info('Init {} app...'.format(name))

    from eduid_webapp.email.views import email_views

    app.register_blueprint(email_views)

    return app
