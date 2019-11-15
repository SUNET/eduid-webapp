# -*- coding: utf-8 -*-
from datetime import datetime, timedelta
from uuid import uuid4
from flask import Blueprint, request, redirect, url_for
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT

from eduid_common.api.utils import urlappend
from eduid_common.session import session
from eduid_common.session.namespaces import SamlRequestInfo, LoginRequest
from eduid_common.authn.idp_saml import parse_saml_request
from eduid_webapp.saml_idp.app import current_idp_app as current_app

__author__ = 'lundberg'

from eduid_webapp.saml_idp.misc import get_login_response_authn

idp_views = Blueprint('idp', __name__, url_prefix='', template_folder='templates')


@idp_views.route('/', methods=['GET'])
def index():
    # TODO: Redirect to landing page?
    return "hello idp"


@idp_views.route('/sso/redirect', methods=['GET'])
def sso_redirect():
    current_app.logger.debug('--- SSO ---')
    current_app.logger.debug(f'{request.method}: {request.path}')
    saml_request_info = SamlRequestInfo(
        saml_request=request.args.get('SAMLRequest'),
        relay_state=request.args.get('RelayState'),
        binding=BINDING_HTTP_REDIRECT,
    )
    request_args = {
        'SAMLRequest': saml_request_info.saml_request,
        'RelayState': saml_request_info.relay_state,
        'SigAlg': request.args.get('SigAlg'),
        'Signature': request.args.get('Signature')
    }
    current_app.logger.debug(f'request args: {request_args}')
    parsed_saml_request = parse_saml_request(request_params=request_args, binding=saml_request_info.binding,
                                             idp=current_app.saml2_server, logger=current_app.logger,
                                             debug=current_app.debug)

    current_app.logger.debug(f'REQ_INFO: {parsed_saml_request._req_info}')
    # TODO: Check for SSO cookie
    # TODO: Check which AuthnContext the SP expects

    # We don't know who is trying to log in
    request_id = str(uuid4())
    session.saml_idp.requests[request_id] = saml_request_info

    session.login.requests[request_id] = LoginRequest(
        # TODO: mfa
        return_endpoint_url=url_for('idp.return_url', request_id=request_id),
        expires_at=datetime.utcnow() + timedelta(seconds=300),  # TODO: Use expire time from SAML request
    )

    login_uri = urlappend(current_app.config.login_uri, request_id)
    current_app.logger.info("Redirecting user to login app {!s}".format(login_uri))
    return redirect(login_uri)


@idp_views.route('/sso/post', methods=['POST'])
def sso_post():
    # TODO
    binding = BINDING_HTTP_POST
    return 'Not implemented'


@idp_views.route('/return/<request_id>', methods=['GET'])
def return_url(request_id):
    saml_request = session.saml_idp.requests.get(request_id)
    if not saml_request:
        return 'Login timeout, please try again'
    user = current_app.
    response_authn = get_login_response_authn(saml_request, user)

    saml_response = self._make_saml_response(response_authn, resp_args, user, ticket, self.sso_session)

    binding_out = resp_args['binding_out']
    destination = resp_args['destination']
    http_args = ticket.saml_req.apply_binding(resp_args, ticket.RelayState, str(saml_response))

    # INFO-Log the SSO session id and the AL and destination
    self.logger.info('{!s}: response authn={!s}, dst={!s}'.format(ticket.key,
                                                                  response_authn,
                                                                  destination))
    self._fticks_log(relying_party=resp_args.get('sp_entity_id', destination),
                     authn_method=response_authn.class_ref,
                     user_id=str(user.user_id),
                     )

    return eduid_idp.mischttp.create_html_response(binding_out, http_args, self.start_response, self.logger)
