# -*- coding: utf-8 -*-

from dataclasses import dataclass, field
from typing import Mapping, Optional

from eduid_common.config.base import FlaskConfig

__author__ = 'lundberg'


@dataclass
class IdpConfig(FlaskConfig):
    """
    Configuration for the idp app
    """
    pysaml2_config: Mapping = field(default_factory=dict)
    login_service_uri: str = '/login/'
    sso_session_cookie_name: str = 'idpauthn'
    sso_permanent_session_lifetime: int = 600
    default_eppn_scope: Optional[str] = 'eduid.se'
    default_scoped_affiliation: Optional[str] = 'affiliate@eduid.se'
    fticks_secret_key: Optional[str] = None
