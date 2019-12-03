# -*- coding: utf-8 -*-
from typing import Optional, List

from flask import Blueprint, render_template, request, make_response, redirect

from eduid_common.api.decorators import require_user, MarshalWith, UnmarshalWith
from eduid_common.api.exceptions import EduidTooManyRequests, EduidForbidden
from eduid_common.authn.idp_authn import AuthnData
from eduid_common.session import session
from eduid_common.session.namespaces import LoginResponse
from eduid_common.session.sso_session import SSOSession
from eduid_userdb import User
from eduid_webapp.login.app import current_login_app as current_app
from eduid_webapp.login.helpers import set_cookie

__author__ = 'lundberg'

login_views = Blueprint('login', __name__, url_prefix='', template_folder='templates')


@login_views.route('/<request_id>', methods=['GET', 'POST'])
def login(request_id):
    current_app.logger.info('LOGIN ENDPOINT')
    if request.method == 'POST':
        current_app.logger.info('LOGIN ENDPOINT POST')

        current_app.logger.debug(f'do_verify parsed query :\n{request.form}')
        if not request.form.get('username') or not request.form.get('password'):
            current_app.logger.debug('Credentials not supplied')
            return render_template('login.jinja2', error_message='Credentials not supplied')

        try:
            login_data = {
                'username': request.form['username'].strip(),
                'password': request.form['password'],
            }
            authn_data = current_app.authn.password_authn(login_data, lookup_user=_lookup_user)
            if not authn_data:
                current_app.logger.debug('Unknown user or wrong password.')
                return render_template('login.jinja2', request_id=request_id, error_message='Login incorrect')
        except EduidTooManyRequests as e:
            current_app.logger.info(e)
            return render_template('error.jinja2', heading='Too many requests',
                                   message='Access cannot be granted at this time. Please try again later.')
        except EduidForbidden as e:
            current_app.logger.info(e)
            return render_template('error.jinja2', heading='Access denied',
                                   message=f'Access to the requested service could not be granted.'
                                           f' The service might have requested a "confirmed" identity.'
                                           f'Visit the eduID dashboard to confirm your identity.')

        #TODO: Split here

        login_request = session.login.requests.get(request_id)
        if not login_request:
            return render_template('error.jinja2', heading='Login timeout',
                                   message='The request took too long to complete, please try to log in again.')
        # TODO: actions
        #check_for_pending_actions(self.context, user, ticket, self.sso_session)

        session.common.eppn = authn_data.user.eppn
        sso_session_id = _create_sso_session(authn_data.user, request_id, [authn_data])

        # Create SSO cookie
        res = redirect(login_request.return_endpoint_url, Response=current_app.response_class)
        current_app.logger.debug(f'Set sso session cookie')
        set_cookie(config=current_app.config, response=res, value=sso_session_id)

        # Now that the user has authenticated and a SSO session has been created, redirect the users browser back to
        # the return url of the calling interface.
        session.login.responses[request_id] = LoginResponse(expires_at=login_request.expires_at,
                                                            sso_session_id=sso_session_id)
        current_app.logger.debug(f'Redirect => {login_request.return_endpoint_url}')
        return res

    return render_template('login.jinja2', request_id=request_id)


def _create_sso_session(user: User, request_id: str, authninfo: List[AuthnData]) -> str:
    sso_session = SSOSession(user_id=user.user_id, authn_request_id=request_id,
                             authn_credentials=authninfo)
    # This session contains information about the fact that the user was authenticated. It is
    # used to avoid requiring subsequent authentication for the same user during a limited
    # period of time, by storing the session-id in a browser cookie.
    sso_session_id = current_app.sso_sessions.add_session(user.user_id, sso_session.to_dict())
    # INFO-Log the request id (sha1 of SAMLrequest) and the sso_session
    current_app.logger.info(f'login sso_session={sso_session.public_id}, user={user}')
    return sso_session_id.decode('utf-8')


def _lookup_user(username: Optional[str]) -> Optional[User]:
    """
    Load IdPUser from userdb.

    :param username: string
    :return: user found in database
    """
    _user = None
    if isinstance(username, str):
        if '@' in username:
            _user = current_app.central_userdb.get_user_by_mail(username.lower(), raise_on_missing=False)
        if not _user:
            _user = current_app.central_userdb.get_user_by_eppn(username.lower(), raise_on_missing=False)
    if not _user:
        # username will be ObjectId if this is a lookup using an existing SSO session
        _user = current_app.central_userdb.get_user_by_id(username, raise_on_missing=False)
    return _user
