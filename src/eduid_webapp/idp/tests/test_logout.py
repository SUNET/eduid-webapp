import logging
import os
from enum import Enum
from typing import Any, Dict, Tuple

from flask import Response as FlaskResponse
from mock import patch
from saml2 import BINDING_SOAP
from saml2.mdstore import destinations
from saml2.response import AuthnResponse, LogoutResponse

from eduid_common.api.app import EduIDBaseApp
from vccs_client import VCCSClient

from eduid_webapp.idp.settings.common import IdPConfig
from eduid_webapp.idp.tests.test_app import IdPTests, LoginState

logger = logging.getLogger(__name__)

HERE = os.path.abspath(os.path.dirname(__file__))


class LogoutState(Enum):
    S0_REQUEST_FAILED = 'request-failed'
    S1_LOGGED_OUT = 'logged_out'


class IdPTestApp(EduIDBaseApp):
    def __init__(self, name: str, config: Dict[str, Any], **kwargs):
        self.config = IdPConfig.init_config(ns='webapp', app_name=name, test_config=config)
        super().__init__(name, **kwargs)


class IdPTestLogout(IdPTests):
    def test_basic_logout(self):
        with self.browser.session_transaction() as sess:
            # Patch the VCCSClient so we do not need a vccs server
            with patch.object(VCCSClient, 'authenticate'):
                VCCSClient.authenticate.return_value = True
                reached_state, response = self._try_login()
                assert reached_state == LoginState.S5_LOGGED_IN

            authn_response = self.parse_saml_authn_response(response)

            reached_state, response = self._try_logout(authn_response, BINDING_SOAP)
            assert reached_state == LogoutState.S1_LOGGED_OUT

            logout_response = self.parse_saml_logout_response(response, BINDING_SOAP)
            assert logout_response.response.status.status_code.value == 'urn:oasis:names:tc:SAML:2.0:status:Success'

    def parse_saml_logout_response(self, response: FlaskResponse, binding: str) -> LogoutResponse:
        xmlstr = response.data
        return self.saml2_client.parse_logout_request_response(xmlstr, binding)

    def _try_logout(self, authn_response: AuthnResponse, binding: str) -> Tuple[LogoutState, FlaskResponse]:
        """
        Try logging out using the IdP.

        :return: Information about how far we got (reached LogoutState) and the last response instance.
        """
        session_info = authn_response.session_info()
        name_id = session_info['name_id']

        srvs = self.saml2_client.metadata.single_logout_service(self.idp_entity_id, binding, 'idpsso')
        destination = destinations(srvs)[0]
        session_indexes = [session_info['session_index']]

        req_id, request = self.saml2_client.create_logout_request(
            destination, self.idp_entity_id, name_id=name_id, reason='', expire=None, session_indexes=session_indexes,
        )

        relay_state = 'testing-testing'
        http_info = self.saml2_client.apply_binding(binding, request, destination, relay_state, sign=False)

        path = self._extract_path_from_url(http_info['url'])
        headers = {}
        # convert list of tuples (name, value) into dict
        for hdr in http_info['headers']:
            k, v = hdr
            headers[k] = v

        if http_info['method'] == 'POST':
            resp = self.browser.post(path, headers=headers, data=http_info['data'])
            if resp.status_code != 200:
                return LogoutState.S0_REQUEST_FAILED, resp
        else:
            raise RuntimeError('Unknown HTTP method')

        return LogoutState.S1_LOGGED_OUT, resp
