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

from saml2.ident import code
from flask import session, request, redirect, current_app
from eduid_common.authn.loa import get_loa
from eduid_webapp.authn.acs_registry import acs_action

import logging
logger = logging.getLogger(__name__)


@acs_action('login-action')
def login_action(session_info, user):

    logger.info("User {!r} logging in (eduPersonPrincipalName: {!r})".format(
        user.user_id,
        user.eppn))
    session['_saml2_session_name_id'] = code(session_info['name_id'])
    session['eduPersonPrincipalName'] = user.eppn
    loa = get_loa(current_app.config.get('AVAILABLE_LOA'), session_info)
    session['eduPersonAssurance'] = loa
    session.persist()

    # redirect the user to the view where he came from
    relay_state = request.form.get('RelayState', '/')
    logger.debug('Redirecting to the RelayState: ' + relay_state)
    response = redirect(location=relay_state)
    session.set_cookie(response)
    return response