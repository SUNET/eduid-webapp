# -*- coding: utf-8 -*-
__author__ = 'lundberg'

import pprint
from dataclasses import replace
from typing import Optional

from eduid_common.authn import assurance
from eduid_common.authn.idp_saml import IdP_SAMLRequest, parse_saml_request, AuthnInfo, ResponseArgs
from eduid_common.session.namespaces import SamlRequestInfo, LoginResponse
from eduid_common.session.sso_session import SSOSession
from eduid_userdb import User
from eduid_webapp.saml_idp.app import current_idp_app as current_app
from eduid_webapp.saml_idp.attributes import get_saml_attributes


def get_saml_request(saml_request_info: SamlRequestInfo, sig_alg: Optional[str] = None,
                     signature: Optional[str] = None) -> IdP_SAMLRequest:
    request_args = {
        'SAMLRequest': saml_request_info.saml_request,
        'RelayState': saml_request_info.relay_state,
        'SigAlg': sig_alg,
        'Signature': signature
    }
    current_app.logger.debug(f'request args: {request_args}')
    return parse_saml_request(request_params=request_args, binding=saml_request_info.binding,
                              idp=current_app.saml2_server, logger=current_app.logger, debug=current_app.debug)


def get_requested_authn_context(saml_req: IdP_SAMLRequest) -> Optional[str]:
    """
    Check if the SP has explicit Authn preferences in the metadata (some SPs are not
    capable of conveying this preference in the RequestedAuthnContext)
    """
    res = saml_req.get_requested_authn_context()
    attributes = saml_req.sp_entity_attributes

    if 'http://www.swamid.se/assurance-requirement' in attributes:
        # XXX don't just pick the first one from the list - choose the most applicable one somehow.
        new_authn = attributes['http://www.swamid.se/assurance-requirement'][0]
        current_app.logger.debug(f'Entity {saml_req.sp_entity_id} has AuthnCtx preferences in metadata. '
                                 f'Overriding {res} -> {new_authn}')
        res = new_authn

    return res


def get_login_response_authn(saml_request: IdP_SAMLRequest, user: User, login_response: LoginResponse) -> AuthnInfo:
    """
    Figure out what AuthnContext to assert in the SAML response.

    The 'highest' Assurance-Level (AL) asserted is basically min(ID-proofing-AL, Authentication-AL).

    What AuthnContext is asserted is also heavily influenced by what the SP requested.

    :param saml_request: State for this request
    :param user: The user for whom the assertion will be made
    :param login_response: Data from the login app
    :return: Authn information
    """
    current_app.logger.debug(f'MFA credentials logged in the ticket: {login_response.mfa_action_creds}')
    current_app.logger.debug(f'External MFA credential logged in the ticket: {login_response.mfa_action_external}')
    current_app.logger.debug(f'Credentials used in this SSO session:\n{current_app.sso_session.authn_credentials}')
    current_app.logger.debug(f'User credentials:\n{user.credentials.to_list()}')

    # Decide what AuthnContext to assert based on the one requested in the request
    # and the authentication performed

    req_authn_context = get_requested_authn_context(saml_request)

    resp_authn = assurance.response_authn(req_authn_context, user, current_app.sso_session, current_app.logger)

    current_app.logger.debug("Response Authn context class: {!r}".format(resp_authn))

    try:
        current_app.logger.debug("Asserting AuthnContext {!r} (requested: {!r})".format(
            resp_authn, req_authn_context))
    except AttributeError:
        current_app.logger.debug("Asserting AuthnContext {!r} (none requested)".format(resp_authn))

    # Augment the AuthnInfo with the authn_timestamp before returning it
    return replace(resp_authn, instant=current_app.sso_session.authn_timestamp)


def make_saml_response(authn_info: AuthnInfo, resp_args: ResponseArgs, user: User,
                       saml_request: IdP_SAMLRequest, sso_session: SSOSession) -> str:
    """
    Create the SAML response using pysaml2 create_authn_response().

    :param authn_info: Info about SAML authentication stuff
    :param resp_args: pysaml2 response arguments
    :param user: user object
    :param saml_request: SAML request info
    :param sso_session: SSO session from persistent storage

    :return: SAML response in lxml format
    """
    attributes = get_saml_attributes(user, current_app.config)
    # Add a list of credentials used in a private attribute that will only be
    # released to the eduID authn component
    attributes['eduidIdPCredentialsUsed'] = [x['cred_id'] for x in sso_session.authn_credentials]
    for k, v in authn_info.authn_attributes.items():
        if k in attributes:
            _previous = attributes[k]
            current_app.logger.debug(f'Overwriting user attribute {k} ({repr(_previous)})'
                                     f' with authn attribute value {repr(v)}')
        else:
            current_app.logger.debug(f'Adding attribute {k} with value from authn process: {v}')
        attributes[k] = v
    # Only perform expensive parse/pretty-print if debugging
    if current_app.debug:
        _attributes = pprint.pformat(attributes)
        _resp_args = pprint.pformat(resp_args)
        _resp_authn = pprint.pformat(authn_info)
        current_app.logger.debug(f'Creating an AuthnResponse: user {user}\n\n'
                                 f'Attributes:\n{_attributes},\n\n'
                                 f'Response args:\n{_resp_args},\n\n'
                                 f'Authn:\n{_resp_authn}')

    saml_response = saml_request.make_saml_response(attributes, user.eppn, authn_info, resp_args)

    return str(saml_response)