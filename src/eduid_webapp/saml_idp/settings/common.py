# -*- coding: utf-8 -*-

from dataclasses import dataclass, field
from typing import Mapping

from eduid_common.config.base import FlaskConfig

__author__ = 'lundberg'


@dataclass
class IdpConfig(FlaskConfig):
    """
    Configuration for the idp app
    """
    pysaml2_config: Mapping = field(default_factory=dict)
    login_uri: str = '/login/'
    sso_permanent_session_lifetime: int = 600



