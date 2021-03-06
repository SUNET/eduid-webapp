#
# Copyright (c) 2015 NORDUnet A/S
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

__author__ = 'eperez'

from typing import Optional

from eduid_common.session.logindata import SSOLoginData
from eduid_userdb.actions import Action
from eduid_userdb.idp import IdPUser

from eduid_webapp.idp.app import current_idp_app as current_app


def add_actions(user: IdPUser, ticket: SSOLoginData) -> Optional[Action]:
    """
    Add an action requiring the user to accept a new version of the Terms of Use,
    in case the IdP configuration points to a version the user hasn't accepted.

    This function is called by the IdP when it iterates over all the registered
    action plugins entry points.

    :param user: the authenticating user
    :param ticket: the SSO login data
    """
    version = current_app.conf.tou_version
    interval = current_app.conf.tou_reaccept_interval

    if user.tou.has_accepted(version, interval):
        current_app.logger.debug(f'User has already accepted ToU version {version!r}')
        return None

    if not current_app.actions_db:
        current_app.logger.warning('No actions_db - aborting ToU action')
        return None

    if current_app.actions_db.has_actions(user.eppn, action_type='tou', params={'version': version}):
        return None

    current_app.logger.debug(f'User must accept ToU version {version!r}')
    return current_app.actions_db.add_action(user.eppn, action_type='tou', preference=100, params={'version': version})
