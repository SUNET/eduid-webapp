#
# Copyright (c) 2019 SUNET
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

import os
from copy import deepcopy
from typing import List, Optional
from six.moves import configparser


_CONFIG_SECTION = 'eduid_idp'


INTEGER_VALUES = [
        'NUM_THREADS',
        'LISTEN_PORT',
        'MAX_AUTHN_FAILURES_PER_MONTH',
        'LOGIN_STATE_TTL',
        'REDIS_PORT',
        'SHARED_SESSION_TTL',
]

BOOLEAN_VALUES = [
        'VERIFY_REQUEST_SIGNATURES',
        'INSECURE_COOKIES',
]

LIST_VALUES = [
        'STATUS_TEST_USERNAMES',
        'REDIS_SENTINEL_HOSTS',
        'ACTION_PLUGINS',
]

class IdPConfig(object):

    """
    Class holding IdP application configuration.

    :param raw_config: None or a dict with default values
    """

    def __init__(self, raw_config: Optional[dict]):
        defaults = deepcopy(raw_config)
        self.config = configparser.RawConfigParser(defaults)
        self._parsed_lists: dict = {}
        self.section = _CONFIG_SECTION

    def __getitem__(self, key: str, default=None):

        if key in INTEGER_VALUES:
            return self.config.getint(self.section, key)

        elif key in BOOLEAN_VALUES:
            return self.config.getboolean(self.section, key)

        elif key in LIST_VALUES:
            if key not in self._parsed_lists:
                self._parsed_lists[key] = _comma_split(self.config, self.section, key)
            return self._parsed_lists[key]

        elif key == 'CONTENT_PACKAGES':
            if key in  self._parsed_lists:
                return self._parsed_lists[key]
            value = self.config.get(self.section, 'content_packages')
            res = []
            for this in value.split(','):
                this = this.strip()
                name, _sep, path, = this.partition(':')
                res.append((name, path))
            self._parsed_lists[key] = res
            return res

        else:
            return self.config.get(self.section, key)


def _comma_split(config, section, name: str) -> List[str]:
    """ Parse a list of comma-separated strings, e.g: 'foo,bar' into ['foo', 'bar'] """
    value = config.get(section, name)
    if not value:
        return []
    return [x.strip() for x in value.split(',')]
