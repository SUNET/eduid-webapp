# -*- coding: utf-8 -*-

import logging
from defusedxml import ElementTree as DefusedElementTree

__author__ = 'lundberg'


logger = logging.getLogger(__name__)


def log_assertion_id(saml_response: str, request_id: str, sso_session_id: str) -> None:
    """
    Log the assertion id, which _might_ be required by Kantara.
    """
    printed = False
    try:
        parser = DefusedElementTree.DefusedXMLParser()
        xml = DefusedElementTree.XML(saml_response, parser)

        # For debugging, it is very useful to get the full SAML response pretty-printed in the logfile directly
        logger.debug(f'Created AuthNResponse :\n\n{DefusedElementTree.tostring(xml)}\n\n')
        printed = True

        attrs = xml.attrib
        assertion = xml.find('{urn:oasis:names:tc:SAML:2.0:assertion}Assertion')
        logger.info(f'{request_id}: sso_session_id={sso_session_id}, id={attrs["ID"]},'
                    f' in_response_to={attrs["InResponseTo"]}, assertion_id={assertion.get("ID")}')

        return DefusedElementTree.tostring(xml)
    except Exception as exc:
        logger.debug(f'Could not parse message as XML: {repr(exc)}')
        if not printed:
            # Fall back to logging the whole response
            logger.info(f'{request_id}: authn response: {saml_response}')
