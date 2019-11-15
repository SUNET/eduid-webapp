# -*- coding: utf-8 -*-
__author__ = 'lundberg'

from eduid_common.authn import assurance
from eduid_common.session.logindata import SSOLoginData


def get_login_response_authn(: SSOLoginData, user: User) -> AuthnInfo:
    """
    Figure out what AuthnContext to assert in the SAML response.

    The 'highest' Assurance-Level (AL) asserted is basically min(ID-proofing-AL, Authentication-AL).

    What AuthnContext is asserted is also heavily influenced by what the SP requested.

    :param ticket: State for this request
    :param user: The user for whom the assertion will be made
    :return: Authn information
    """
    self.logger.debug('MFA credentials logged in the ticket: {}'.format(ticket.mfa_action_creds))
    self.logger.debug('External MFA credential logged in the ticket: {}'.format(ticket.mfa_action_external))
    self.logger.debug('Credentials used in this SSO session:\n{}'.format(self.sso_session.authn_credentials))
    self.logger.debug('User credentials:\n{}'.format(user.credentials.to_list()))

    # Decide what AuthnContext to assert based on the one requested in the request
    # and the authentication performed

    req_authn_context = get_requested_authn_context(self.context.idp, ticket.saml_req, self.logger)

    try:
        resp_authn = assurance.response_authn(req_authn_context, user, self.sso_session, self.logger)
    except WrongMultiFactor as exc:
        self.logger.info('Assurance not possible: {!r}'.format(exc))
        raise eduid_idp.error.Forbidden('SWAMID_MFA_REQUIRED')
    except MissingMultiFactor as exc:
        self.logger.info('Assurance not possible: {!r}'.format(exc))
        raise eduid_idp.error.Forbidden('MFA_REQUIRED')
    except AssuranceException as exc:
        self.logger.info('Assurance not possible: {!r}'.format(exc))
        raise MustAuthenticate()

    self.logger.debug("Response Authn context class: {!r}".format(resp_authn))

    try:
        self.logger.debug("Asserting AuthnContext {!r} (requested: {!r})".format(
            resp_authn, req_authn_context))
    except AttributeError:
        self.logger.debug("Asserting AuthnContext {!r} (none requested)".format(resp_authn))

    # Augment the AuthnInfo with the authn_timestamp before returning it
    return replace(resp_authn, instant=self.sso_session.authn_timestamp)