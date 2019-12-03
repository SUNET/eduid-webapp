# -*- coding: utf-8 -*-
from datetime import datetime, timedelta
from typing import Optional
from uuid import uuid4
from flask import Blueprint, request, redirect, url_for, make_response
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT
from werkzeug.exceptions import BadRequest

from eduid_common.api.utils import urlappend
from eduid_common.authn.assurance import WrongMultiFactor, MissingMultiFactor, AssuranceException
from eduid_common.session import session
from eduid_common.session.namespaces import SamlRequestInfo, LoginRequest
from eduid_common.authn.idp_saml import parse_saml_request, IdP_SAMLRequest
from eduid_webapp.saml_idp.app import current_idp_app as current_app

from eduid_webapp.saml_idp import kantara, fticks

from eduid_webapp.saml_idp.saml_helpers import get_login_response_authn, get_saml_request, make_saml_response

__author__ = 'lundberg'

sso_views = Blueprint('sso', __name__, url_prefix='/sso', template_folder='templates')


@sso_views.route('/redirect', methods=['GET'])
def sso_redirect():
    current_app.logger.debug('--- SSO ---')
    current_app.logger.debug(f'{request.method}: {request.path}')
    saml_request_info = SamlRequestInfo(
        saml_request=request.args.get('SAMLRequest'),
        relay_state=request.args.get('RelayState'),
        binding=BINDING_HTTP_REDIRECT,
    )
    parsed_saml_request = get_saml_request(saml_request_info, request.args.get('SigAlg'),
                                           request.args.get('Signature'))

    request_id = str(uuid4())
    session.saml_idp.requests[request_id] = saml_request_info
    current_app.logger.debug(f'REQ_INFO: {parsed_saml_request._req_info}')

    # Check for SSO cookie
    current_app.logger.debug(f'request.cookies: {request.cookies}')
    if 'idpauthn' in request.cookies:
        sso_session_id = bytes(request.cookies['idpauthn'], encoding='utf8')
        sso_session = current_app.sso_sessions.get_session(sid=sso_session_id, return_object=True)
        current_app.logger.debug(f'sso_session: {sso_session}')




    # TODO: Check which AuthnContext the SP expects

    # We don't know who is trying to log in, the SSO session has wrong AuthnContext or force authn is true


    session.login.requests[request_id] = LoginRequest(
        # TODO: mfa
        return_endpoint_url=url_for('sso.return_url', request_id=request_id, _external=True),
        expires_at=datetime.utcnow() + timedelta(seconds=300),  # TODO: Use expire time from SAML request
    )

    login_service_uri = urlappend(current_app.config.login_service_uri, request_id)
    current_app.logger.info("Redirecting user to login service {!s}".format(login_service_uri))
    return redirect(login_service_uri)


@sso_views.route('/post', methods=['POST'])
def sso_post():
    # TODO
    binding = BINDING_HTTP_POST
    return 'Not implemented'


@sso_views.route('/return/<request_id>', methods=['GET'])
def return_url(request_id):
    saml_request_info = session.saml_idp.requests.get(request_id)
    login_response = session.login.responses.get(request_id)
    sso_session = current_app.sso_sessions.get_session(sid=login_response.sso_session_id.encode(), return_object=True)
    if saml_request_info is None or login_response is None:
        return 'Login timeout, please try again'
    saml_request = get_saml_request(saml_request_info=saml_request_info)
    user = current_app.central_userdb.get_user_by_eppn(session.common.eppn)
    try:
        response_authn = get_login_response_authn(saml_request, user, login_response, sso_session)
    except WrongMultiFactor as exc:
        current_app.logger.info('Assurance not possible: {!r}'.format(exc))
        return 'SWAMID_MFA_REQUIRED'
    except MissingMultiFactor as exc:
        current_app.logger.info('Assurance not possible: {!r}'.format(exc))
        return 'MFA_REQUIRED'
    except AssuranceException as exc:
        current_app.logger.info('Assurance not possible: {!r}'.format(exc))
        return 'Login failed, please try again'

    try:
        resp_args = saml_request.get_response_args(bad_request=BadRequest, key=request_id)
    except BadRequest as exc:
        current_app.logger.info('Bad request: {!r}'.format(exc))
        return f'Bad request: {exc.description}'

    saml_response = make_saml_response(response_authn, resp_args, user, saml_request, sso_session)
    binding_out = resp_args['binding_out']
    destination = resp_args['destination']
    http_args = saml_request.apply_binding(resp_args, saml_request_info.relay_state, saml_response)

    kantara.log_assertion_id(saml_response, request_id, login_response.sso_session_id)
    # INFO-Log the SSO session id and the AL and destination
    current_app.logger.info(f'{request_id}: response authn={response_authn}, dst={destination}')
    fticks.log(hmac_key=current_app.config.fticks_secret_key,
               entity_id=current_app.saml2_server.config.entityid,
               relying_party=resp_args.get('sp_entity_id', destination),
               authn_method=response_authn.class_ref,
               user_id=str(user.user_id),
               )

    if binding_out == BINDING_HTTP_REDIRECT:
        for header in http_args["headers"]:
            if header[0] == "Location":
                resp = redirect(header[1], Response=current_app.response_class)
    if binding_out == BINDING_HTTP_POST:
        resp = make_response(http_args['data'])
        resp.headers.extend(http_args['headers'])
        return resp

    current_app.logger.error(f'Unknown binding: {binding_out}')
    return f'Unknown binding: {binding_out}'
