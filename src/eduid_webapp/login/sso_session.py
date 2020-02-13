# -*- coding: utf-8 -*-
from __future__ import annotations

from dataclasses import field, dataclass, asdict
from operator import attrgetter
from typing import List, Dict, Optional, Mapping, Any

from flask import request
from werkzeug import Response

from eduid_common.session.namespaces import LoginResponse, SessionAuthnData, LoginRequest
from eduid_common.session.sso_cache import SSOSessionId
from eduid_webapp.login.app import current_login_app as current_app
from eduid_webapp.login.settings.common import LoginConfig

__author__ = 'lundberg'


@dataclass
class SSOSession:
    eppn: str
    public_id: str
    authentication_data: Dict[str, List[SessionAuthnData]] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> SSOSession:
        authentication_data = {}
        for key, values in data.get('authentication_data').items():
            authentication_data[key] = [SessionAuthnData.from_dict(value) for value in values]
        return cls(eppn=data['eppn'], public_id=data['public_id'], authentication_data=authentication_data)


def create_sso_session(user_eppn: str, login_response: LoginResponse, request_id: str,
                       public_session_id: str) -> SSOSessionId:
    sso_session = SSOSession(eppn=user_eppn, public_id=public_session_id)
    sso_session.authentication_data[request_id] = login_response.credentials_used
    # This session contains information about the fact that the user was authenticated. It is
    # used to avoid requiring subsequent authentication for the same user during a limited
    # period of time, by storing the session-id in a browser cookie.
    sso_session_id = current_app.sso_sessions.add_session(user_eppn, asdict(sso_session))
    # INFO-Log the request id and the sso_session
    current_app.logger.info(f'{request_id}: sso_session={sso_session.public_id}')
    return sso_session_id


def update_sso_session(user_eppn: str, login_response: LoginResponse, request_id: str,
                       public_session_id: str) -> SSOSessionId:
    # TODO: Fake update until broken update code is fixed
    return create_sso_session(user_eppn, login_response, request_id, public_session_id)


def get_sso_session() -> Optional[SSOSession]:
    sso_session_id = request.cookies.get(current_app.config.sso_session_cookie_name)
    current_app.logger.debug(f'Cookies: {request.cookies}')
    current_app.logger.debug(f'Looking for cookie with name: {current_app.config.sso_session_cookie_name}')
    current_app.logger.debug(f'Found sso session id: {sso_session_id}')
    if sso_session_id:
        b_sso_session_id = bytes(sso_session_id, encoding='utf-8')
        session_data = current_app.sso_sessions.get_session(b_sso_session_id)
        if session_data:
            return SSOSession.from_dict(session_data)
        current_app.logger.warning(f'SSO session with id {b_sso_session_id} not found.')
    return None


def verify_sso_session(sso_session: SSOSession, login_request: LoginRequest) -> None:
    """Check if the data in the sso session is valid for this login request"""
    if not sso_session:
        return None
    # TODO: What else do we need to implement here?
    # We have an sso session, so we know who this user is
    login_request.eppn = sso_session.eppn
    login_request.sso_session_public_id = sso_session.public_id
    # Add previous valid authentications to our current login request
    sso_authn = []
    for key, values in sso_session.authentication_data.items():
        sso_authn.extend(values)
    current_app.logger.debug(f'SSO_AUTHN PRE SORT:  {sso_authn}')
    sso_authn_data = sorted(sso_authn, key=attrgetter('authn_ts'))
    current_app.logger.debug(f'SSO_AUTHN POST SORT: {sso_authn}')
    # TODO: Actually verify if we still want to use the previous credentials
    login_request.verified_credentials = sso_authn_data


def set_sso_cookie(config: LoginConfig, response: Response, value: str) -> None:
    """
    Set the SSO session cookie.
    """
    cookie_name = config.get('sso_session_cookie_name')
    max_age = int(config.get('sso_permanent_session_lifetime'))
    cookie_domain = config.get('sso_session_cookie_domain') or config.get('session_cookie_domain')
    cookie_path = config.get('sso_session_cookie_path') or config.get('session_cookie_path')
    cookie_secure = config.get('sso_session_cookie_secure') or config.get('session_cookie_secure')
    cookie_httponly = config.get('sso_session_cookie_httponly') or config.get('session_cookie_httponly')
    cookie_samesite = config.get('sso_session_cookie_samesite') or config.get('session_cookie_samesite')
    response.set_cookie(cookie_name,
                        value=value,
                        domain=cookie_domain,
                        path=cookie_path,
                        secure=cookie_secure,
                        httponly=cookie_httponly,
                        samesite=cookie_samesite,
                        max_age=max_age
                        )
