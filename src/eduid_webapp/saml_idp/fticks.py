# -*- coding: utf-8 -*-

from typing import Optional

import logging
import time
import hmac
from hashlib import sha256


logger = logging.getLogger(__name__)

__author__ = 'lundberg'


def log(hmac_key: Optional[str], entity_id: str, relying_party: str, authn_method: str, user_id: str) -> None:
    """
    Perform SAML F-TICKS logging, for statistics in the SWAMID federation.
    format_string: 'F-TICKS/SWAMID/2.0#TS={ts}#RP={rp}#AP={ap}#PN={pn}#AM={am}#'

    :param hmac_key: hmac key
    :param entity_id: IdP entity id
    :param relying_party: The entity id of the relying party (SP).
    :param authn_method: The URN of the authentication method used.
    :param user_id: Unique user id.
    """
    if not hmac_key:
        return
    _timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    _anon_userid = hmac.new(hmac_key.encode('ascii'), msg=user_id.encode('ascii'), digestmod=sha256).hexdigest()
    msg = f'F-TICKS/SWAMID/2.0#TS={_timestamp}#RP={relying_party}#AP={entity_id}#PN={_anon_userid}#AM={authn_method}#'
    logger.info(msg)
