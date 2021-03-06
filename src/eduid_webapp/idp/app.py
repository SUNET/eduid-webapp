# -*- coding: utf-8 -*-
#
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
#     3. Neither the name of the SUNET nor the names of its
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

import pprint
from base64 import b64decode
from typing import Any, Mapping, Optional, cast

from flask import current_app

from eduid_common.api import translation
from eduid_common.api.app import EduIDBaseApp
from eduid_common.authn.utils import init_pysaml2
from eduid_common.config.parsers import load_config
from eduid_common.session import session
from eduid_userdb.actions import ActionDB
from eduid_userdb.idp import IdPUserDb

from eduid_webapp.idp import idp_authn
from eduid_webapp.idp.settings.common import IdPConfig
from eduid_webapp.idp.sso_cache import SSOSessionCache
from eduid_webapp.idp.sso_session import SSOSession, SSOSessionId

__author__ = 'ft'


class IdPApp(EduIDBaseApp):
    def __init__(self, config: IdPConfig, userdb: Optional[Any] = None, **kwargs: Any) -> None:
        super().__init__(config, **kwargs)

        self.conf = config

        # Init dbs
        # self.private_userdb = IdPUserDB(self.conf.mongo_uri)
        # Initiate external modules
        translation.init_babel(self)

        # Connecting to MongoDB can take some time if the replica set is not fully working.
        # Log both 'starting' and 'started' messages.
        self.logger.info("eduid-IdP server starting")

        self.logger.debug(f'Loading PySAML2 server using cfgfile {config.pysaml2_config}')
        self.IDP = init_pysaml2(config.pysaml2_config)

        if config.sso_session_mongo_uri:
            self.logger.info('Config parameter sso_session_mongo_uri ignored. Used mongo_uri instead.')

        if config.mongo_uri is None:
            raise RuntimeError('Mongo URI is not optional for the IdP')
        _session_ttl = config.sso_session_lifetime * 60
        self.sso_sessions = SSOSessionCache(config.mongo_uri, ttl=_session_ttl)

        _login_state_ttl = (config.login_state_ttl + 1) * 60
        self.authn_info_db = None
        self.actions_db = None

        if config.mongo_uri and config.actions_app_uri:
            self.actions_db = ActionDB(config.mongo_uri)
            self.logger.info("configured to redirect users with pending actions")
        else:
            self.logger.debug("NOT configured to redirect users with pending actions")

        if userdb is None:
            # This is used in tests at least
            userdb = IdPUserDb(logger=None, mongo_uri=config.mongo_uri, db_name=config.userdb_mongo_database)
        self.userdb = userdb
        self.authn = idp_authn.IdPAuthn(config=config, userdb=self.userdb)
        self.logger.info('eduid-IdP application started')

    def _lookup_sso_session(self) -> Optional[SSOSession]:
        """
        Locate any existing SSO session for this request.

        :returns: SSO session if found (and valid)
        """
        session = self._lookup_sso_session2()
        if session:
            self.logger.debug(f'SSO session for user {session.idp_user} found in IdP cache: {session}')
            _age = session.minutes_old
            if _age > self.conf.sso_session_lifetime:
                self.logger.debug(f'SSO session expired (age {_age} minutes > {self.conf.sso_session_lifetime})')
                return None
            self.logger.debug(f'SSO session is still valid (age {_age} minutes <= {self.conf.sso_session_lifetime})')
        return session

    def _lookup_sso_session2(self) -> Optional[SSOSession]:
        """
        See if a SSO session exists for this request, and return the data about
        the currently logged in user from the session store.

        :return: Data about currently logged in user
        """
        _sso = None

        _session_id = self.get_sso_session_id()
        if _session_id:
            _sso = self.sso_sessions.get_session(_session_id, self.userdb)
            self.logger.debug(f'Looked up SSO session using session ID {repr(_session_id)}:\n{_sso}')

        if not _sso:
            self.logger.debug("SSO session not found using 'id' parameter or IdP SSO cookie")

            if session.idp.sso_cookie_val is not None:
                self.logger.debug('Found potential sso_cookie_val in the eduID session')
                _other_session_id = SSOSessionId(session.idp.sso_cookie_val.encode('ascii'))
                _other_sso = self.sso_sessions.get_session(_other_session_id, self.userdb)
                if _other_sso is not None:
                    # Debug issues with browsers not returning updated SSO cookie values.
                    # Only log partial cookie value since it allows impersonation if leaked.
                    self.logger.info(
                        f'Found no SSO session, but found one from session.idp.sso_cookie_val '
                        f'({session.idp.sso_cookie_val[:8]}...)'
                    )
            return None
        self.logger.debug(f'Re-created SSO session {_sso}')
        return _sso

    def get_sso_session_id(self) -> Optional[SSOSessionId]:
        """
        Get the SSO session id from the IdP SSO cookie, with fallback to hopefully unused 'id' query string parameter.

        :return: SSO session id
        """
        # local import to avoid import-loop
        from eduid_webapp.idp.mischttp import parse_query_string, read_cookie

        _session_id = read_cookie(self.conf.sso_cookie.key)
        if _session_id:
            # The old IdP base64 encoded the session_id, try to  remain interoperable. Fingers crossed.
            _decoded_session_id = b64decode(_session_id)
            self.logger.debug(
                f'Got SSO session ID from IdP SSO cookie {repr(_session_id)} -> {repr(_decoded_session_id)}'
            )
            return SSOSessionId(_decoded_session_id)

        query = parse_query_string()
        if query and 'id' in query:
            self.logger.warning('Found "id" in query string - this was thought to be obsolete')
            self.logger.debug("Parsed query string :\n{!s}".format(pprint.pformat(query)))
            _session_id = query['id']
            self.logger.debug(f'Got SSO session ID from query string: {_session_id}')
            return SSOSessionId(bytes(_session_id, 'ascii'))

        return None


current_idp_app = cast(IdPApp, current_app)


def init_idp_app(name: str = 'idp', test_config: Optional[Mapping[str, Any]] = None) -> IdPApp:
    """
    :param name: The name of the instance, it will affect the configuration loaded.
    :param test_config: Override configuration - used in tests.

    :return: the flask app
    """
    config = load_config(typ=IdPConfig, app_name=name, ns='webapp', test_config=test_config)

    app = IdPApp(config, handle_exceptions=False)

    # Register views
    from eduid_webapp.idp.views import idp_views

    app.register_blueprint(idp_views)

    from eduid_webapp.idp.exceptions import init_exception_handlers

    app = init_exception_handlers(app)

    app.logger.info(f'{name} initialized')
    return app
