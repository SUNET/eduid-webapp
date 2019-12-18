# -*- coding: utf-8 -*-
#
# Copyright (c) 2013, 2014, 2015 NORDUnet A/S
#                           2019 SUNET
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
# Author : Fredrik Thulin <fredrik@thulin.net>
#

import logging
import pprint
from typing import FrozenSet

from eduid_userdb import User
from eduid_webapp.saml_idp.settings.common import SAMLIdpConfig

logger = logging.getLogger(__name__)

# default list of attributes to pass on to pysaml2
SAML_ATTRIBUTES = frozenset({'displayName',
                             'eduPersonAssurance',
                             'eduPersonEntitlement',
                             'eduPersonPrincipalName',
                             'eduPersonScopedAffiliation',
                             'givenName',
                             'mail',
                             'norEduPersonNIN',
                             'preferredLanguage',
                             'sn',
                             })


def get_saml_attributes(user: User, config: SAMLIdpConfig, filter_attributes: FrozenSet[str] = SAML_ATTRIBUTES) -> dict:
    """
    Return a dict of SAML attributes for a user.

    Note that this is _all_ parts of the user that this IdP knows how to express as
    SAML attributes. It is not necessarily the attributes that will actually be released.

    :param user: User object
    :param config: IdP config
    :param filter_attributes: Filter to apply

    :return: SAML attributes
    """
    attributes_in = user.to_dict(old_userdb_format=True)
    attributes = {}
    for approved in filter_attributes:
        if approved in attributes_in:
            attributes[approved] = attributes_in.pop(approved)
    logger.debug('Discarded non-attributes:\n{!s}'.format(pprint.pformat(attributes_in)))
    attributes1 = make_scoped_eppn(attributes, config)
    attributes2 = add_scoped_affiliation(attributes1, config)
    attributes = add_eduperson_assurance(attributes2, user)
    return attributes


def make_scoped_eppn(attributes: dict, config: SAMLIdpConfig) -> dict:
    """
    Add scope to unscoped eduPersonPrincipalName attributes before releasing them.

    What scope to add, if any, is currently controlled by the configuration parameter
    `default_eppn_scope'.

    :param attributes: Attributes of a user
    :param config: IdP configuration data
    :return: New attributes
    """
    eppn = attributes.get('eduPersonPrincipalName')
    scope = config.default_eppn_scope
    if not eppn or not scope:
        return attributes
    if '@' not in eppn:
        attributes['eduPersonPrincipalName'] = eppn + '@' + scope
    return attributes


def add_scoped_affiliation(attributes: dict, config: SAMLIdpConfig) -> dict:
    """
    Add eduPersonScopedAffiliation if configured, and not already present.

    This default affiliation is currently controlled by the configuration parameter
    `default_scoped_affiliation'.

    :param attributes: Attributes of a user
    :param config: IdP configuration data

    :return: New attributes
    """
    epsa = 'eduPersonScopedAffiliation'
    scoped_affiliation = config.default_scoped_affiliation
    if epsa not in attributes and scoped_affiliation:
        attributes[epsa] = scoped_affiliation
    return attributes


def add_eduperson_assurance(attributes: dict, user: User) -> dict:
    """
    Add an eduPersonAssurance attribute indicating the level of id-proofing
    a user has achieved, regardless of current session authentication strength.

    :param attributes: Attributes of a user
    :param user: The user in question

    :return: New attributes
    """
    attributes['eduPersonAssurance'] = 'http://www.swamid.se/policy/assurance/al1'
    _verified_nins = [x for x in user.nins.to_list() if x.is_verified]
    if _verified_nins:
        attributes['eduPersonAssurance'] = 'http://www.swamid.se/policy/assurance/al2'
    return attributes
