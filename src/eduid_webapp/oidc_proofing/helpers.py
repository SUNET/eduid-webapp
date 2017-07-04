# -*- coding: utf-8 -*-
from __future__ import absolute_import

import requests
import json
from flask import current_app

from eduid_userdb.proofing.element import NinProofingElement
from eduid_userdb.logs import OidcProofing
from eduid_common.api.utils import get_unique_hash
from eduid_common.api.helpers import verify_nin_for_user, number_match_proofing
from eduid_userdb.proofing import OidcProofingState

__author__ = 'lundberg'


def create_proofing_state(user, nin):
    """
    :param user: Proofing user
    :param nin: National Identity Number

    :type user: eduid_userdb.proofing.ProofingUser
    :type nin: str

    :return: OidcProofingState
    :rtype: eduid_userdb.proofing.OidcProofingState
    """
    state = get_unique_hash()
    nonce = get_unique_hash()
    token = get_unique_hash()
    nin_element = NinProofingElement(number=nin, application='oidc_proofing', verified=False)
    proofing_state = OidcProofingState({'eduPersonPrincipalName': user.eppn, 'nin': nin_element.to_dict(),
                                        'state': state, 'nonce': nonce, 'token': token})
    return proofing_state


def do_authn_request(proofing_state, claims_request, redirect_url):
    """
    :param proofing_state: Proofing state for user
    :param claims_request: Requested claims
    :param redirect_url: authn response url

    :type proofing_state: eduid_userdb.proofing.OidcProofingState
    :type claims_request: oic.oic.message.ClaimsRequest
    :type redirect_url: str

    :return: success
    :rtype: bool
    """
    oidc_args = {
        'client_id': current_app.oidc_client.client_id,
        'response_type': 'code',
        'scope': ['openid'],
        'redirect_uri': redirect_url,
        'state': proofing_state.state,
        'nonce': proofing_state.nonce,
        'claims': claims_request.to_json()
    }
    current_app.logger.debug('AuthenticationRequest args:')
    current_app.logger.debug(oidc_args)

    response = requests.post(current_app.oidc_client.authorization_endpoint, data=oidc_args)
    if response.status_code == 200:
        current_app.logger.debug('Authentication request delivered to provider {!s}'.format(
            current_app.config['PROVIDER_CONFIGURATION_INFO']['issuer']))
        return True
    current_app.logger.error('Bad response from OP: {!s} {!s} {!s}'.format(response.status_code,
                                                                           response.reason, response.content))
    return False


def create_proofing_log_entry(user, proofing_state, vetting_by):
    """
    :param user: Central userdb user
    :param proofing_state: Proofing state for user
    :param vetting_by: OIDC proofing supplier

    :type user: eduid_userdb.user.User
    :type proofing_state: eduid_userdb.proofing.OidcProofingState
    :type vetting_by: six.string_types

    :return: Proofing log entry element
    :rtype: eduid_userdb.log.OidcProofing
    """
    current_app.logger.info('Getting address for user {!r}'.format(user))
    # Lookup official address via Navet
    address = current_app.msg_relay.get_postal_address(proofing_state.nin.number)
    # Transaction id is the same data as used for the QR code or seed data for the freja app
    transaction_id = '1' + json.dumps({'nonce': proofing_state.nonce, 'token': proofing_state.token})
    oidc_proof = OidcProofing(user, created_by=proofing_state.nin.created_by, nin=proofing_state.nin.number,
                              vetting_by=vetting_by, transaction_id=transaction_id, user_postal_address=address,
                              proofing_version='2017v1')
    return oidc_proof


def handle_seleg_userinfo(user, proofing_state, userinfo):
    """
    :param user: Central userdb user
    :param proofing_state: Proofing state for user
    :param userinfo: userinfo from OP

    :type user: eduid_userdb.user.User
    :type proofing_state: eduid_userdb.proofing.OidcProofingState

    :type userinfo: dict
    :return: None
    """
    current_app.logger.info('Verifying NIN from seleg for user {}'.format(user))
    number = userinfo['identity']
    # Check if the self professed NIN is the same as the NIN returned by the vetting provider
    if number_match_proofing(user, proofing_state, number):
        proofing_log_entry = create_proofing_log_entry(user, proofing_state, vetting_by='seleg')
        verify_nin_for_user(user, proofing_state, proofing_log_entry)


def handle_freja_eid_userinfo(user, proofing_state, userinfo):
    """
    :param user: Central userdb user
    :param proofing_state: Proofing state for user
    :param userinfo: userinfo from OP

    :type user: eduid_userdb.user.User
    :type proofing_state: eduid_userdb.proofing.OidcProofingState
    :type userinfo: dict

    :return: None
    """
    current_app.logger.info('Verifying NIN from Freja eID for user {}'.format(user))
    number = userinfo['freja_proofing']['ssn']
    if number_match_proofing(user, proofing_state, number):
        proofing_log_entry = create_proofing_log_entry(user, proofing_state, vetting_by='freja eid')
        verify_nin_for_user(user, proofing_state, proofing_log_entry)

