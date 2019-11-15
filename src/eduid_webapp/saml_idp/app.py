# -*- coding: utf-8 -*-

from flask import current_app, Flask
from saml2.server import Server as Saml2Server

from eduid_common.api.app import get_app_config
from eduid_common.session.sso_cache import SSOSessionCacheMDB
from eduid_userdb.actions import ActionDB
from eduid_webapp.saml_idp.settings.common import IdpConfig

__author__ = 'lundberg'


class SAMLIdpApp(Flask):

    def __init__(self, name, config):
        config = get_app_config(name, config)
        super(SAMLIdpApp, self).__init__(name, config)
        self.config = IdpConfig(**config)
        self.saml2_server: Saml2Server
        self.actions_db: ActionDB

        # Initialize pysaml2
        self.saml2_server = Saml2Server(config_file=self.config.pysaml2_config)

        # Init dbs
        self.actions_db = ActionDB(db_uri=self.config.mongo_uri)
        self.sso_sessions = SSOSessionCacheMDB(uri=self.config.mongo_uri, logger=self.logger.getChild('sso_sessions'),
                                               ttl=self.config.sso_permanent_session_lifetime * 60)


def get_current_app() -> SAMLIdpApp:
    """Teach pycharm about SAMLIdpApp"""
    return current_app  # type: ignore


current_idp_app = get_current_app()


def init_idp_app(name: str, config: dict = None) -> SAMLIdpApp:
    """
    :param name: The name of the instance, it will affect the configuration loaded.
    :param config: any additional configuration settings. Specially useful
                   in test cases
    """
    app = SAMLIdpApp(name, config)

    # Register views
    from eduid_webapp.saml_idp.views import idp_views
    app.register_blueprint(idp_views, url_prefix=app.config.application_root)

    app.logger.info('{!s} initialized'.format(name))
    return app
