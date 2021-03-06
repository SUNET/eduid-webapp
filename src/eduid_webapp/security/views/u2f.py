# -*- coding: utf-8 -*-


import six
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from flask import Blueprint
from OpenSSL import crypto
from u2flib_server.u2f import begin_authentication, begin_registration, complete_authentication, complete_registration

from eduid_common.api.decorators import MarshalWith, UnmarshalWith, require_user
from eduid_common.api.messages import FluxData, error_response, success_response
from eduid_common.api.schemas.u2f import U2FEnrollResponseSchema, U2FSignResponseSchema
from eduid_common.api.utils import save_and_sync_user
from eduid_common.session import session
from eduid_userdb import User
from eduid_userdb.credentials import U2F
from eduid_userdb.security import SecurityUser

from eduid_webapp.security.app import current_security_app as current_app
from eduid_webapp.security.helpers import SecurityMsg, compile_credential_list, credentials_to_registered_keys
from eduid_webapp.security.schemas import (
    BindU2FRequestSchema,
    EnrollU2FTokenResponseSchema,
    ModifyU2FTokenRequestSchema,
    RemoveU2FTokenRequestSchema,
    SecurityResponseSchema,
    SignWithU2FTokenResponseSchema,
    VerifyWithU2FTokenRequestSchema,
    VerifyWithU2FTokenResponseSchema,
)

__author__ = 'lundberg'


u2f_views = Blueprint('u2f', __name__, url_prefix='/u2f', template_folder='templates')


@u2f_views.route('/enroll', methods=['GET'])
@MarshalWith(EnrollU2FTokenResponseSchema)
@require_user
def enroll(user: User):
    user_u2f_tokens = user.credentials.filter(U2F)
    if user_u2f_tokens.count >= current_app.conf.u2f_max_allowed_tokens:
        current_app.logger.error(
            'User tried to register more than {} tokens.'.format(current_app.conf.u2f_max_allowed_tokens)
        )
        return error_response(message=SecurityMsg.max_tokens)
    registered_keys = credentials_to_registered_keys(user_u2f_tokens)
    enrollment = begin_registration(current_app.conf.u2f_app_id, registered_keys)
    session['_u2f_enroll_'] = enrollment.json
    current_app.stats.count(name='u2f_token_enroll')
    return U2FEnrollResponseSchema().load(enrollment.data_for_client)


@u2f_views.route('/bind', methods=['POST'])
@UnmarshalWith(BindU2FRequestSchema)
@MarshalWith(SecurityResponseSchema)
@require_user
def bind_view(user: User, version: str, registration_data: str, client_data: str, description: str = '') -> FluxData:
    return bind(
        user, version, registration_data, client_data, description
    )  # TODO: Unsplit bind and bind_view after demo


def bind(user: User, version: str, registration_data: str, client_data: str, description='') -> FluxData:
    security_user = SecurityUser.from_user(user, current_app.private_userdb)
    enrollment_data = session.pop('_u2f_enroll_', None)
    if not enrollment_data:
        current_app.logger.error('Found no U2F enrollment data in session.')
        return error_response(message=SecurityMsg.missing_data)

    data = {'version': version, 'registrationData': registration_data, 'clientData': client_data}
    device, der_cert = complete_registration(enrollment_data, data, current_app.conf.u2f_valid_facets)

    cert = x509.load_der_x509_certificate(der_cert, default_backend())
    pem_cert = crypto.dump_certificate(crypto.FILETYPE_PEM, cert)
    if not isinstance(pem_cert, six.string_types):
        pem_cert = pem_cert.decode('utf-8')

    u2f_token = U2F(
        version=device['version'],
        keyhandle=device['keyHandle'],
        app_id=device['appId'],
        public_key=device['publicKey'],
        attest_cert=pem_cert,
        description=description,
        created_by='eduid_security',
    )
    security_user.credentials.add(u2f_token)
    save_and_sync_user(security_user)
    current_app.stats.count(name='u2f_token_bind')
    credentials = compile_credential_list(security_user)
    return success_response(payload=dict(credentials=credentials), message=SecurityMsg.u2f_registered)


@u2f_views.route('/sign', methods=['GET'])
@MarshalWith(SignWithU2FTokenResponseSchema)
@require_user
def sign(user: User):
    user_u2f_tokens = user.credentials.filter(U2F)
    if not user_u2f_tokens.count:
        current_app.logger.error('Found no U2F token for user.')
        return error_response(message=SecurityMsg.no_u2f)

    registered_keys = credentials_to_registered_keys(user_u2f_tokens)
    challenge = begin_authentication(current_app.conf.u2f_app_id, registered_keys)
    session['_u2f_challenge_'] = challenge.json
    current_app.stats.count(name='u2f_sign')
    return U2FSignResponseSchema().load(challenge.data_for_client)


@u2f_views.route('/verify', methods=['POST'])
@UnmarshalWith(VerifyWithU2FTokenRequestSchema)
@MarshalWith(VerifyWithU2FTokenResponseSchema)
@require_user
def verify(user: User, key_handle: str, signature_data: str, client_data: str):
    challenge = session.pop('_u2f_challenge_')
    if not challenge:
        current_app.logger.error('Found no U2F challenge data in session.')
        return error_response(message=SecurityMsg.no_challenge)

    data = {'keyHandle': key_handle, 'signatureData': signature_data, 'clientData': client_data}
    device, c, t = complete_authentication(challenge, data, current_app.conf.u2f_valid_facets)
    current_app.stats.count(name='u2f_verify')
    return {'key_handle': device['keyHandle'], 'counter': c, 'touch': t}


@u2f_views.route('/modify', methods=['POST'])
@UnmarshalWith(ModifyU2FTokenRequestSchema)
@MarshalWith(SecurityResponseSchema)
@require_user
def modify(user: User, credential_key: str, description: str) -> FluxData:
    security_user = SecurityUser.from_user(user, current_app.private_userdb)
    token_to_modify = security_user.credentials.filter(U2F).find(credential_key)
    if not token_to_modify:
        current_app.logger.error('Did not find requested U2F token for user.')
        return error_response(message=SecurityMsg.no_token)

    if len(description) > current_app.conf.u2f_max_description_length:
        current_app.logger.error(
            'User tried to set a U2F token description longer than {}.'.format(
                current_app.conf.u2f_max_description_length
            )
        )
        return error_response(message=SecurityMsg.long_desc)

    token_to_modify.description = description
    save_and_sync_user(security_user)
    current_app.stats.count(name='u2f_token_modify')
    credentials = compile_credential_list(security_user)
    return success_response(payload=dict(credentials=credentials))


@u2f_views.route('/remove', methods=['POST'])
@UnmarshalWith(RemoveU2FTokenRequestSchema)
@MarshalWith(SecurityResponseSchema)
@require_user
def remove(user: User, credential_key) -> FluxData:
    security_user = SecurityUser.from_user(user, current_app.private_userdb)
    token_to_remove = security_user.credentials.filter(U2F).find(credential_key)
    if token_to_remove:
        security_user.credentials.remove(credential_key)
        save_and_sync_user(security_user)
        current_app.stats.count(name='u2f_token_remove')

    credentials = compile_credential_list(security_user)
    return success_response(payload=dict(credentials=credentials), message=SecurityMsg.rm_u2f_success)
