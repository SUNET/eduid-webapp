# -*- coding: utf-8 -*-

from __future__ import absolute_import

from six.moves.urllib_parse import urlencode, urlsplit, urlunsplit
from flask import Blueprint, current_app
from flask import request, session, redirect, abort, make_response


from eduid_common.api.decorators import require_user, MarshalWith
from eduid_common.api.schemas.csrf import CSRFResponse
from eduid_common.api.utils import verify_relay_state, urlappend
from eduid_common.authn.acs_registry import get_action, schedule_action
from eduid_common.authn.utils import get_location
from eduid_common.authn.eduid_saml2 import BadSAMLResponse
from eduid_userdb.proofing.user import ProofingUser
from eduid_userdb.credentials import U2F

from eduid_webapp.eidas.helpers import create_authn_request, parse_authn_response, create_metadata

__author__ = 'lundberg'

eidas_views = Blueprint('eidas', __name__, url_prefix='', template_folder='templates')


@eidas_views.route('/', methods=['GET'])
@MarshalWith(CSRFResponse)
@require_user
def index(user):
    return {}


@eidas_views.route('/verify-token/<credential_id>', methods=['GET'])
@require_user
def verify_token(user, credential_id):
    current_app.logger.debug('verify-token called with credential_id: {}'.format(credential_id))
    proofing_user = ProofingUser.from_user(user, current_app.private_userdb)

    url = urlappend(current_app.config['DASHBOARD_URL'], 'security')
    scheme, netloc, path, query_string, fragment = urlsplit(url)

    # Check if requested key id is a mfa token and if the user used that to log in
    token_to_verify = proofing_user.credentials.filter(U2F).find(credential_id)
    if not token_to_verify:
        new_query_string = urlencode({'msg': ':ERROR:eidas.token_not_found'})
        url = urlunsplit((scheme, netloc, path, new_query_string, fragment))
        return redirect(url)

    if token_to_verify.key not in session['eduidIdPCredentialsUsed']:
        new_query_string = urlencode({'msg': ':ERROR:eidas.token_not_in_credentials_used'})
        url = urlunsplit((scheme, netloc, path, new_query_string, fragment))
        return redirect(url)

    # Set token key id in session
    session['verify_token_action_key_id'] = credential_id
    session.persist()

    # Request a authentication from idp
    required_loa = 'loa3'
    return _authn('token-verify-action', required_loa, force_authn=True)


def _authn(action, required_loa, force_authn=False, redirect_url='/'):
    relay_state = verify_relay_state(request.args.get('next', redirect_url), redirect_url)
    idp = request.args.get('idp')
    current_app.logger.debug('Requested IdP: {}'.format(idp))
    idps = current_app.saml2_config.metadata.identity_providers()
    current_app.logger.debug('IdPs from metadata: {}'.format(idps))

    if idp in idps:
        authn_request = create_authn_request(relay_state, idp, required_loa, force_authn=force_authn)
        schedule_action(action)
        current_app.logger.info('Redirecting the user to {} for {}'.format(idp, action))
        return redirect(get_location(authn_request))
    abort(make_response('IdP ({}) not found in metadata'.format(idp), 404))


@eidas_views.route('/saml2-acs', methods=['POST'])
def assertion_consumer_service():
    """
    Assertion consumer service, receives POSTs from SAML2 IdP's
    """

    if 'SAMLResponse' not in request.form:
        abort(400)

    saml_response = request.form['SAMLResponse']
    try:
        authn_response = parse_authn_response(saml_response)
        current_app.logger.debug('Verified authn response: {}'.format(authn_response))

        session_info = authn_response.session_info()

        current_app.logger.debug('Auth response:\n{!s}\n\n'.format(authn_response))
        current_app.logger.debug('Session info:\n{!s}\n\n'.format(session_info))

        action = get_action()
        return action(session_info)
    except BadSAMLResponse as e:
        return make_response(str(e), 400)


@eidas_views.route('/saml2-metadata')
def metadata():
    """
    Returns an XML with the SAML 2.0 metadata for this
    SP as configured in the saml2_settings.py file.
    """
    data = create_metadata(current_app.saml2_config)
    response = make_response(data.to_string(), 200)
    response.headers['Content-Type'] = "text/xml; charset=utf8"
    return response