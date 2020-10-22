#
# Copyright (c) 2013, 2014 NORDUnet A/S. All rights reserved.
# Copyright 2012 Roland Hedberg. All rights reserved.
#
# See the file eduid-IdP/LICENSE.txt for license statement.
#
# Author : Fredrik Thulin <fredrik@thulin.net>
#          Roland Hedberg
#

"""
Code handling Single Log Out requests.
"""
import pprint
from typing import Dict

import saml2
from flask import request
from saml2 import BINDING_HTTP_POST, BINDING_HTTP_REDIRECT, BINDING_SOAP
from saml2.request import LogoutRequest
from saml2.s_utils import error_status_factory, exception_trace
from saml2.samlp import STATUS_PARTIAL_LOGOUT, STATUS_RESPONDER, STATUS_SUCCESS, STATUS_UNKNOWN_PRINCIPAL
from werkzeug.exceptions import BadRequest, InternalServerError
from werkzeug.wrappers import Response as WerkzeugResponse

from eduid_common.authn.idp_saml import gen_key
from eduid_common.session import sso_session
from eduid_common.session.sso_cache import SSOSessionId

from eduid_webapp.idp import mischttp
from eduid_webapp.idp.app import current_idp_app as current_app
from eduid_webapp.idp.service import Service
from eduid_webapp.idp.util import maybe_xml_to_string

# -----------------------------------------------------------------------------
# === Single log out ===
# -----------------------------------------------------------------------------


class SLO(Service):
    """
    Single Log Out service.
    """

    def redirect(self):
        """ Expects a HTTP-redirect request """

        _dict = self.unpack_redirect()
        return self.perform_logout(_dict, BINDING_HTTP_REDIRECT)

    def post(self):
        """ Expects a HTTP-POST request """

        _dict = self.unpack_post()
        return self.perform_logout(_dict, BINDING_HTTP_POST)

    def soap(self):
        """
        Single log out using HTTP_SOAP binding
        """
        _dict = self.unpack_soap()
        return self.perform_logout(_dict, BINDING_SOAP)

    def unpack_soap(self) -> Dict[str, str]:
        """
        Turn a SOAP request into the common format of a dict.

        :return: dict with 'SAMLRequest' and 'RelayState' items
        """
        # Need to get the body without sanitation
        data = request.stream.read().decode('utf-8')
        return {
            'SAMLRequest': data,
            'RelayState': '',
        }

    def perform_logout(self, info: Dict[str, str], binding: str) -> WerkzeugResponse:
        """
        Perform logout. Means remove SSO session from IdP list, and a best
        effort to contact all SPs that have received assertions using this
        SSO session and letting them know the user has been logged out.

        :param info: Dict with SAMLRequest and possibly RelayState
        :param binding: SAML2 binding as string
        :return: SAML StatusCode
        """
        current_app.logger.debug('--- Single Log Out Service ---')
        if not info:
            raise BadRequest('Error parsing request or no request')

        request = info["SAMLRequest"]
        req_key = gen_key(request)

        try:
            req_info = current_app.IDP.parse_logout_request(request, binding)
            assert isinstance(req_info, saml2.request.LogoutRequest)
            current_app.logger.debug(f'Parsed Logout request ({binding}):\n{req_info.message}')
        except Exception:
            current_app.logger.exception(f'Failed parsing logout request')
            current_app.logger.debug(f'_perform_logout {binding}:\n{pprint.pformat(info)}')
            raise BadRequest('Failed parsing logout request')

        req_info.binding = binding
        if 'RelayState' in info:
            req_info.relay_state = info['RelayState']

        # look for the subject
        subject = req_info.subject_id()
        if subject is not None:
            current_app.logger.debug(f'Logout subject: {subject.text.strip()}')
        # XXX should verify issuer (a.k.a. sender()) somehow perhaps
        current_app.logger.debug(f'Logout request sender : {req_info.sender()}')

        _name_id = req_info.message.name_id
        _session_id = current_app.get_sso_session_id()
        _username = None
        if _session_id:
            # If the binding is REDIRECT, we can get the SSO session to log out from the
            # client idpauthn cookie
            session_ids = [SSOSessionId(_session_id)]
        else:
            # For SOAP binding, no cookie is sent - only NameID. Have to figure out
            # the user based on NameID and then destroy *all* the users SSO sessions
            # unfortunately.
            _username = current_app.IDP.ident.find_local_id(_name_id)
            current_app.logger.debug(f'Logout message name_id: {_name_id!r} found username {_username!r}')
            session_ids = current_app.sso_sessions.get_sessions_for_user(_username)

        current_app.logger.debug(
            f'Logout resources: name_id {_name_id!r} username {_username!r}, session_ids {session_ids!r}'
        )

        if session_ids:
            status_code = self._logout_session_ids(session_ids, req_key)
        else:
            # No specific SSO session(s) were found, we have no choice but to logout ALL
            # the sessions for this NameID.
            status_code = self._logout_name_id(_name_id, req_key)

        current_app.logger.debug(f'Logout of sessions {session_ids!r} / NameID {_name_id!r} result : {status_code!r}')
        return self._logout_response(req_info, status_code, req_key)

    def _logout_session_ids(self, session_ids, req_key) -> str:
        """
        Terminate one or more specific SSO sessions.

        :param session_ids: List of db keys in SSO session database
        :param req_key: Logging id of request
        :return: SAML StatusCode
        :rtype: string
        """
        fail = 0
        for this in session_ids:
            current_app.logger.debug("Logging out SSO session with key: {!s}".format(this))
            try:
                _data = current_app.sso_sessions.get_session(this)
                if not _data:
                    raise KeyError('Session not found')
                _sso = sso_session.from_dict(_data)
                res = current_app.sso_sessions.remove_session(this)
                current_app.logger.info(
                    f'{req_key}: logout sso_session={_sso.public_id!r}, age={_sso.minutes_old!r}m, result={bool(res)!r}'
                )
            except KeyError:
                current_app.logger.info(f'{req_key}: logout sso_key={this!r}, result=not_found')
                res = 0
            if not res:
                fail += 1
        if fail:
            if fail == len(session_ids):
                return STATUS_RESPONDER
            return STATUS_PARTIAL_LOGOUT
        return STATUS_SUCCESS

    def _logout_name_id(self, name_id, req_key):
        """
        Terminate ALL SSO sessions found using this NameID.

        This is not as nice as _logout_session_ids(), as it would log a user
        out of sessions across multiple devices - probably not the expected thing
        to happen from a user perspective when clicking Logout on their phone.

        :param name_id: NameID from LogoutRequest
        :param req_key: Logging id of request
        :return: SAML StatusCode
        :rtype: string
        """
        if not name_id:
            current_app.logger.debug('No NameID provided for logout')
            return STATUS_UNKNOWN_PRINCIPAL
        try:
            # remove the authentication
            # XXX would be useful if remove_authn_statements() returned how many statements it actually removed
            current_app.IDP.session_db.remove_authn_statements(name_id)
            current_app.logger.info(f'{req_key}: logout name_id={name_id!r}')
        except KeyError:
            current_app.logger.exception(f'Failed removing authn')
            raise InternalServerError()
        return STATUS_SUCCESS

    def _logout_response(
        self, req_info: LogoutRequest, status_code: str, req_key: str, sign_response: bool = True
    ) -> WerkzeugResponse:
        """
        Create logout response.

        :param req_info: Logout request
        :param status_code: logout result (e.g. 'urn:oasis:names:tc:SAML:2.0:status:Success')
        :param req_key: SAML request id
        :param sign_response: cryptographically sign response or not
        :return: HTML response

        :type req_info: saml2.request.LogoutRequest
        :type status_code: string
        :type req_key: string
        :type sign_response: bool
        :rtype: string
        """
        current_app.logger.debug(
            f'LOGOUT of \'{req_info.subject_id()}\' by \'{req_info.sender()}\', success={status_code!r}'
        )
        if req_info.binding != BINDING_SOAP:
            bindings = [BINDING_HTTP_REDIRECT, BINDING_HTTP_POST]
            binding, destination = current_app.IDP.pick_binding(
                'single_logout_service', bindings, entity_id=req_info.sender()
            )
            bindings = [binding]
        else:
            bindings = [BINDING_SOAP]
            destination = ""

        status = None  # None == success in create_logout_response()
        if status_code != saml2.samlp.STATUS_SUCCESS:
            status = error_status_factory((status_code, 'Logout failed'))
            current_app.logger.debug(f'Created \'logout failed\' status based on {status_code!r} : {status!r}')

        issuer = current_app.IDP._issuer(current_app.IDP.config.entityid)
        response = current_app.IDP.create_logout_response(
            req_info.message, bindings, status, sign=sign_response, issuer=issuer
        )
        # Only perform expensive parse/pretty-print if debugging
        if current_app.config.debug:
            xmlstr = maybe_xml_to_string(response)
            current_app.logger.debug(f'Logout SAMLResponse :\n\n{xmlstr}\n\n')

        ht_args = current_app.IDP.apply_binding(
            bindings[0], str(response), destination, req_info.relay_state, response=True
        )
        # current_app.logger.debug("Apply bindings result :\n{!s}\n\n".format(pprint.pformat(ht_args)))

        # INFO-Log the SAML request ID, result of logout and destination
        current_app.logger.info(f'{req_key}: logout status={status_code!r}, dst={destination}')

        # XXX old code checked 'if req_info.binding == BINDING_HTTP_REDIRECT:', but it looks like
        # it would be more correct to look at bindings[0] here, since `bindings' is what was used
        # with create_logout_response() and apply_binding().
        if req_info.binding != bindings[0]:
            current_app.logger.debug(
                f'Creating response with binding {bindings[0]!r} instead of {req_info.binding!r} used before'
            )

        res = mischttp.create_html_response(bindings[0], ht_args)

        # Delete the SSO session cookie in the browser
        res.delete_cookie(
            key='idpauthn', path=current_app.config.session_cookie_path, domain=current_app.config.session_cookie_domain
        )
        return res