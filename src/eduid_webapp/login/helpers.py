# -*- coding: utf-8 -*-

from werkzeug import Response
from eduid_webapp.login.settings.common import LoginConfig

__author__ = 'lundberg'


def set_cookie(config: LoginConfig, response: Response, value: str) -> None:
    """
    Set the SSO session cookie.

    :param response: the response object to carry the cookie
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
