# -*- coding: utf-8 -*-

from __future__ import absolute_import

from eduid_common.authn.utils import get_saml2_config, no_authn_views
from eduid_common.api.app import eduid_init_app
from eduid_common.api import am, msg, debug

__author__ = 'lundberg'


def init_eidas_app(name, config=None):
    """
    :param name: The name of the instance, it will affect the configuration loaded.
    :param config: any additional configuration settings. Specially useful
                   in test cases

    :type name: str
    :type config: dict

    :return: the flask app
    :rtype: flask.Flask
    """

    app = eduid_init_app(name, config)

    app.saml2_config = get_saml2_config(app.config['SAML2_SETTINGS_MODULE'])
    app.config['SAML2_CONFIG'] = app.saml2_config

    # Register views
    from eduid_webapp.eidas.views import eidas_views
    app.register_blueprint(eidas_views)

    # Register view path that should not be authorized
    app = no_authn_views(app, ['/saml2-metadata'])

    # Init dbs

    # Init celery
    app = msg.init_relay(app)
    app = am.init_relay(app, 'eduid_eidas')

    app.logger.info('{!s} initialized'.format(name))
    return app
