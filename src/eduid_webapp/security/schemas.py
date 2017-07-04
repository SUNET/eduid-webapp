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

from marshmallow import fields
from eduid_common.api.schemas.base import FluxStandardAction, EduidSchema


class CredentialSchema(EduidSchema):
    credential_type = fields.String(required=True)
    created_ts = fields.String(required=True)
    success_ts = fields.String(required=True)


class CredentialList(EduidSchema):
    credentials = fields.Nested(CredentialSchema, many=True)
    csrf_token = fields.String(required=True)


class SecurityResponseSchema(FluxStandardAction):
    payload = fields.Nested(CredentialList, only=('credentials', 'csrf_token'))
    csrf_token = fields.String(attribute='csrf_token')


class ChpassCredentialList(EduidSchema):
    credentials = fields.Nested(CredentialSchema, many=True)
    next_url = fields.String(required=True)
    csrf_token = fields.String(required=True)


class ChpassResponseSchema(FluxStandardAction):
    payload = fields.Nested(ChpassCredentialList, only=('credentials',
                    'next_url', 'csrf_token'))
    csrf_token = fields.String(attribute='csrf_token')


class CsrfSchema(EduidSchema):
    csrf_token = fields.String(required=True)


class RedirectSchema(EduidSchema):
    location = fields.String(required=True)


class RedirectResponseSchema(FluxStandardAction):

    payload = RedirectSchema()


class SuggestedPassword(EduidSchema):

    suggested_password = fields.String(required=True)
    csrf_token = fields.String(required=True)


class SuggestedPasswordResponseSchema(FluxStandardAction):

    payload = SuggestedPassword()


class ChangePasswordSchema(EduidSchema):

    old_password = fields.String(required=True)
    new_password = fields.String(required=True)
    csrf_token = fields.String(required=True)


class AccountTerminatedSchema(FluxStandardAction):
    pass