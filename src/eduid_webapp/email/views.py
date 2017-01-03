# -*- coding: utf-8 -*-
#
# Copyright (c) 2016 NORDUnet A/S
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

from __future__ import absolute_import

from flask import Blueprint
from flask import render_template, current_app

from eduid_userdb.element import PrimaryElementViolation
from eduid_userdb.exceptions import UserOutOfSync
from eduid_userdb.mail import MailAddress
from eduid_common.api.decorators import require_dashboard_user, MarshalWith, UnmarshalWith
from eduid_common.api.utils import save_dashboard_user
from eduid_webapp.email.schemas import EmailListPayload, EmailSchema, EmailResponseSchema
from eduid_webapp.email.schemas import VerificationCodeSchema
from eduid_webapp.email.verifications import send_verification_code

email_views = Blueprint('email', __name__, url_prefix='', template_folder='templates')


@email_views.route('/all', methods=['GET'])
@MarshalWith(EmailResponseSchema)
@require_dashboard_user
def get_all_emails(user):
    emails = {'emails': user.mail_addresses.to_list()}
    return EmailListPayload().dump(emails).data


@email_views.route('/new', methods=['POST'])
@UnmarshalWith(EmailSchema)
@MarshalWith(EmailResponseSchema)
@require_dashboard_user
def post_email(user, email, confirmed, primary):
    new_mail = MailAddress(email=email, application='dashboard',
                           verified=False, primary=False)
    user.mail_addresses.add(new_mail)
    try:
        save_dashboard_user(user, dbattr_name='dashboard_userdb')
    except UserOutOfSync:
        return {
            '_status': 'error',
            'error': {'form': 'out_of_sync'}
        }

    send_verification_code(email, user)

    emails = {'emails': user.mail_addresses.to_list()}
    return EmailListPayload().dump(emails).data


@email_views.route('/primary', methods=['POST'])
@UnmarshalWith(EmailSchema)
@MarshalWith(EmailResponseSchema)
@require_dashboard_user
def post_primary(user, email, confirmed, primary):

    try:
        mail = user.mail_addresses.find(email)
    except IndexError:
        return {
            '_status': 'error',
            'error': {'form': 'out_of_sync'}
        }

    if not mail.is_verified:
        return {
            '_status': 'error',
            'error': {'form': 'emails.unconfirmed_address_not_primary'}
        }

    user.mail_addresses.primary = mail.email
    try:
        save_dashboard_user(user, dbattr_name='dashboard_userdb')
    except UserOutOfSync:
        return {
            '_status': 'error',
            'error': {'form': 'out_of_sync'}
        }
    emails = {'emails': user.mail_addresses.to_list()}
    return EmailListPayload().dump(emails).data


@email_views.route('/verify', methods=['POST'])
@UnmarshalWith(VerificationCodeSchema)
@MarshalWith(EmailResponseSchema)
@require_dashboard_user
def verify(user, code, email):
    """
    """
    db = current_app.verifications_db
    state = db.get_state_by_eppn_and_code(user.eppn, code)
    verification = state.verification
    timeout = current_app.config.get('EMAIL_VERIFICATION_TIMEOUT', 24)
    if state.is_expired(timeout):
        msg = "Verification code is expired: {!r}".format(verification)
        current_app.logger.debug(msg)
        return {
            '_status': 'error',
            'error': {'form': 'emails.code_expired'}
        }

    if email != verification.email:
        msg = "Invalid verification code: {!r}".format(verification)
        current_app.logger.debug(msg)
        return {
            '_status': 'error',
            'error': {'form': 'emails.code_invalid'}
        }

    verification.is_verified = True
    verification.verified_ts = datetime.datetime.now()
    verification.verified_by = user.eppn
    state.verification = verification
    current_app.verifications_db.save(state)

    other = current_app.emails_userdbb.get_user_by_mail(email)
    if other and other.mail_addresses.primary and \
            other.mail_addresses.primary.email == email:
        # Promote some other verified e-mail address to primary
        for address in other.mail_addresses.to_list():
            if address.is_verified and address.email != email:
                other.mail_addresses.primary = address.email
                break
        other.mail_addresses.remove(email)
        save_dashboard_user(other, dbattr_name='dashboard_userdb')

    new_email = MailAddress(email = email, application = 'dashboard',
                            verified = True, primary = False)
    if user.mail_addresses.primary is None:
        new_email.is_primary = True
    try:
        user.mail_addresses.add(new_email)
    except DuplicateElementViolation:
        user.mail_addresses.find(email).is_verified = True
        if user.mail_addresses.primary is None:
            user.mail_addresses.find(email).is_primary = True

    try:
        save_dashboard_user(user, dbattr_name='dashboard_userdb')
    except UserOutOfSync:
        return {
            '_status': 'error',
            'error': {'form': 'out_of_sync'}
        }
    emails = {'emails': user.mail_addresses.to_list()}
    return EmailListPayload().dump(emails).data


@email_views.route('/remove', methods=['POST'])
@UnmarshalWith(EmailSchema)
@MarshalWith(EmailResponseSchema)
@require_dashboard_user
def post_remove(user, email, confirmed, primary):
    emails = user.mail_addresses.to_list()
    if len(emails) == 1:
        return {
            '_status': 'error',
            'error': {'form': 'emails.cannot_remove_unique'}
        }

    try:
        user.mail_addresses.remove(email)
    except PrimaryElementViolation:
        new_index = 1 if emails[0].email == email else 0
        user.mail_addresses.primary = emails[new_index].email
        user.mail_addresses.remove(email)

    try:
        save_dashboard_user(user, dbattr_name='dashboard_userdb')
    except UserOutOfSync:
        return {
            '_status': 'error',
            'error': {'form': 'out_of_sync'}
        }

    emails = {'emails': user.mail_addresses.to_list()}
    return EmailListPayload().dump(emails).data


@email_views.route('/resend-code', methods=['POST'])
@UnmarshalWith(EmailSchema)
@MarshalWith(EmailResponseSchema)
@require_dashboard_user
def resend_code(user, email):
    if not user.mail_addresses.find(email):
        current_app.logger.warning('Unknown email in resend_code_action, user {!s}'.format(user))
        return {
            '_status': 'error',
            'error': {'form': 'out_of_sync'}
        }
    
    send_verification_code(email, user)

    emails = {'emails': user.mail_addresses.to_list()}
    return EmailListPayload().dump(emails).data
