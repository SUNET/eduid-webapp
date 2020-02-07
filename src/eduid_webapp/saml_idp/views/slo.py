# -*- coding: utf-8 -*-
from flask import Blueprint

from eduid_webapp.saml_idp.app import current_idp_app as current_app

__author__ = 'lundberg'

slo_views = Blueprint('slo', __name__, url_prefix='/slo', template_folder='templates')


@slo_views.route('/redirect', methods=['GET'])
def slo_redirect():
    current_app.logger.info('SLO REDIRECT called')
    return 'OK'


@slo_views.route('/post', methods=['POST'])
def slo_post():
    current_app.logger.info('SLO POST called')
    return 'OK'


@slo_views.route('/soap', methods=['POST'])
def slo_soap():
    current_app.logger.info('SLO SOAP called')
    return 'OK'


def invalidate_sso_session():
    pass
