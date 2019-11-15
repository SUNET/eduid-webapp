# -*- coding: utf-8 -*-

from flask import current_app

from eduid_common.api import translation
from eduid_common.api.app import EduIDApp
from eduid_common.api.app import get_app_config
from eduid_common.authn.idp_authn import IdPAuthn
from eduid_common.session.sso_cache import SSOSessionCacheMDB
from eduid_webapp.login.settings.common import LoginConfig

__author__ = 'lundberg'


class LoginApp(EduIDApp):

    def __init__(self, name, config):
        config = get_app_config(name, config)
        super(LoginApp, self).__init__(name, config)
        self.config = LoginConfig(**config)
        # Init dbs
        self.sso_sessions = SSOSessionCacheMDB(uri=self.config.mongo_uri, logger=self.logger.getChild('sso_sessions'),
                                               ttl=self.config.sso_permanent_session_lifetime * 60)
        # Init translations
        translation.init_babel(self)
        # Init authn
        self.authn = IdPAuthn(logger=self.logger.getChild('authn'), config=self.config, userdb=self.central_userdb)


def get_current_app() -> LoginApp:
    """Teach pycharm about LoginApp"""
    return current_app  # type: ignore


current_login_app = get_current_app()


def init_login_app(name: str, config: dict):
    """
    :param name: The name of the instance, it will affect the configuration loaded.
    :param config: any additional configuration settings. Specially useful
                   in test cases

    :type name: str
    :type config: dict

    :return: the flask app
    :rtype: flask.Flask
    """

    app = LoginApp(name, config)

    # Register views
    from eduid_webapp.login.views import login_views
    app.register_blueprint(login_views)

    app.logger.info('{!s} initialized'.format(name))
    return app
