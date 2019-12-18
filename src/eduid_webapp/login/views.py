# -*- coding: utf-8 -*-
from typing import Optional
from uuid import uuid4

from flask import Blueprint, render_template, request, redirect

from eduid_common.api.exceptions import EduidTooManyRequests, EduidForbidden
from eduid_common.session import session
from eduid_common.session.namespaces import LoginResponse, SessionAuthnData
from eduid_userdb import User
from eduid_webapp.login.app import current_login_app as current_app

__author__ = 'lundberg'

from eduid_webapp.login.sso_session import create_sso_session, set_sso_cookie

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


        # Create SSO cookie
        public_sso_session_id = str(uuid4())[:18]  # Use half to separate from the private sso session id
        session_autn_data = SessionAuthnData(cred_id=authn_data.credential.credential_id, authn_ts=authn_data.timestamp)
        login_response = LoginResponse(expires_at=login_request.expires_at,
                                       credentials_used=[session_autn_data],
                                       public_sso_session_id=public_sso_session_id)
        sso_session_id = create_sso_session(authn_data.user, login_response, request_id, public_sso_session_id)
        res = redirect(login_request.return_endpoint_url, Response=current_app.response_class)
        current_app.logger.debug(f'Set sso session cookie')
        set_sso_cookie(config=current_app.config, response=res, value=sso_session_id.decode('utf-8'))

        # Update session
        session.common.eppn = authn_data.user.eppn
        session.login.responses[request_id] = login_response

        # Now that the user has authenticated and a SSO session has been created, redirect the users browser back to
        # the return url of the calling interface.
        current_app.logger.debug(f'Redirect => {login_request.return_endpoint_url}')
        return res

    return render_template('login.jinja2', request_id=request_id)


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
