# -*- coding: utf-8 -*-

from flask import current_app
from saml2.server import Server as Saml2Server

from eduid_common.api.app import get_app_config, EduIDApp
from eduid_common.api.debug import log_app_routes
from eduid_common.session.sso_cache import SSOSessionCacheMDB
from eduid_userdb.actions import ActionDB
from eduid_webapp.saml_idp.settings.common import SAMLIdpConfig

__author__ = 'lundberg'


class SAMLIdpApp(EduIDApp):

    def __init__(self, name, config):
        config = get_app_config(name, config)
        super(SAMLIdpApp, self).__init__(name, config)
        self.config = SAMLIdpConfig(**config)
        self.saml2_server: Saml2Server
        self.actions_db: ActionDB

        # Initialize pysaml2
        self.saml2_server = Saml2Server(config_file=self.config.pysaml2_config)

        # Init dbs
        self.actions_db = ActionDB(db_uri=self.config.mongo_uri)


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
    from eduid_webapp.saml_idp.views.root import root_views
    from eduid_webapp.saml_idp.views.sso import sso_views
    from eduid_webapp.saml_idp.views.slo import slo_views
    app.register_blueprint(root_views)
    app.register_blueprint(sso_views)
    app.register_blueprint(slo_views)

    if app.debug:
        log_app_routes(app)

    app.logger.info('{!s} initialized'.format(name))
    return app
