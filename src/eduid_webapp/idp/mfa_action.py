#
# Copyright (c) 2017 NORDUnet A/S
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#     1. Redistributions of source code must retain the above copyright
#        notice, this list of conditions and the following disclaimer.
#     2. Redistributions in binary form must reproduce the above
#        copyright notice, this list of conditions and the following
#        disclaimer in the documentation and/or other materials provided
#        with the distribution.
#     3. Neither the name of the NORDUnet nor the names of its
#        contributors may be used to endorse or promote products derived
#        from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#
import datetime
from typing import List, Optional

from eduid_common.misc.timeutil import utc_now
from eduid_common.session.logindata import ExternalMfaData, SSOLoginData
from eduid_userdb.actions import Action
from eduid_userdb.credentials import U2F, Webauthn
from eduid_userdb.idp.user import IdPUser

from eduid_webapp.idp.app import current_idp_app as current_app
from eduid_webapp.idp.util import get_requested_authn_context

__author__ = 'ft'


RESULT_CREDENTIAL_KEY_NAME = 'cred_key'


def add_actions(user: IdPUser, ticket: SSOLoginData) -> Optional[Action]:
    """
    Add an action requiring the user to login using one or more additional
    authentication factors.

    This function is called by the IdP when it iterates over all the registered
    action plugins entry points.

    :param user: the authenticating user
    :param ticket: the SSO login data
    """
    if not current_app.actions_db:
        current_app.logger.warning('No actions_db - aborting MFA action')
        return None

    require_mfa = False
    requested_authn_context = get_requested_authn_context(ticket.saml_req)
    if requested_authn_context in [
        'https://refeds.org/profile/mfa',
        'https://www.swamid.se/specs/id-fido-u2f-ce-transports',
    ]:
        require_mfa = True

    # Security Keys
    u2f_tokens = user.credentials.filter(U2F).to_list()
    webauthn_tokens = user.credentials.filter(Webauthn).to_list()
    tokens = u2f_tokens + webauthn_tokens

    if not tokens and not require_mfa:
        current_app.logger.debug('User does not have any FIDO tokens registered and SP did not require MFA')
        return None

    existing_actions = current_app.actions_db.get_actions(user.eppn, ticket.key, action_type='mfa')
    if existing_actions and len(existing_actions) > 0:
        current_app.logger.debug('User has existing MFA actions - checking them')
        if check_authn_result(user, ticket, existing_actions):
            for this in ticket.mfa_action_creds.keys():
                current_app.authn.log_authn(user, success=[this], failure=[])
            # TODO: Should we persistently log external mfa usage?
            return None
        current_app.logger.error('User returned without MFA credentials')

    current_app.logger.debug(f'User must authenticate with a token (has {len(tokens)} token(s))')
    return current_app.actions_db.add_action(
        user.eppn,
        action_type='mfa',
        preference=1,
        session=ticket.key,  # XXX double-check that ticket.key is not sensitive to disclose to the user
        params={},
    )


def check_authn_result(user: IdPUser, ticket: SSOLoginData, actions: List[Action]) -> bool:
    """
    The user returned to the IdP after being sent to actions. Check if actions has
    added the results of authentication to the action in the database.

    :param user: the authenticating user
    :param ticket: the SSO login data
    :param actions: Actions in the ActionDB matching this user and session

    :return: MFA action with proof of completion found
    """
    if not current_app.actions_db:
        raise RuntimeError('check_authn_result called without actions_db')

    for this in actions:
        current_app.logger.debug(f'Action {this} authn result: {this.result}')
        if this.result is None:
            continue
        _utc_now = utc_now()
        if this.result.get('success') is True:
            if this.result.get('issuer') and this.result.get('authn_context'):
                # External MFA authentication
                ticket.mfa_action_external = ExternalMfaData(
                    issuer=this.result['issuer'], authn_context=this.result['authn_context'], timestamp=_utc_now
                )
                current_app.logger.debug(
                    f'Removing MFA action completed with external issuer {this.result.get("issuer")}'
                )
                current_app.actions_db.remove_action_by_id(this.action_id)
                return True
            key = this.result.get(RESULT_CREDENTIAL_KEY_NAME)
            cred = user.credentials.find(key)
            if cred:
                ticket.mfa_action_creds[cred.key] = _utc_now
                current_app.logger.debug(f'Removing MFA action completed with {cred}')
                current_app.actions_db.remove_action_by_id(this.action_id)
                return True
            else:
                current_app.logger.error(f'MFA action completed with unknown key {key}')
    return False
