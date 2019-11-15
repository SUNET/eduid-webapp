# -*- coding: utf-8 -*-

from marshmallow import fields

from eduid_common.api.schemas.base import EduidSchema, FluxStandardAction
from eduid_common.api.schemas.csrf import CSRFResponseMixin, CSRFRequestMixin
from eduid_common.api.schemas.validators import validate_nin

__author__ = 'lundberg'


class IdpRequestSchema(EduidSchema, CSRFRequestMixin):
    pass


class IdpResponseSchema(EduidSchema, CSRFResponseMixin):
    pass
