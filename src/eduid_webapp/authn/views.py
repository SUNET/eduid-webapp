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


from flask import request, session, redirect, abort
from flask import current_app, Blueprint

from eduid_common.authn.utils import get_location
from eduid_common.authn.eduid_saml2 import get_authn_request, get_authn_response
from eduid_common.authn.eduid_saml2 import authenticate
from eduid_webapp.authn.acs_registry import get_action, schedule_action

import logging
logger = logging.getLogger(__name__)

authn_views = Blueprint('authn', __name__)


@authn_views.route('/login')
def login():
    """
    login view, redirects to SAML2 IdP
    """
    redirect_url = current_app.config.get('SAML2_LOGIN_REDIRECT_URL', '/')
    came_from = request.args.get('next', redirect_url)
    idp = session.get('idp', None)
    idp = request.args.get('idp', idp)
    authn_request = get_authn_request(current_app.config,
                                      session, came_from, idp)
    schedule_action('login-action')
    logger.debug('Redirecting the user to the IdP')
    return redirect(get_location(authn_request))


@authn_views.route('/saml2-acs', methods=['POST'])
def assertion_consumer_service():
    """
    Assertion consumer service, receives POSTs from SAML2 IdP's
    """
    if 'SAMLResponse' not in request.form:
        abort(400)
    xmlstr = request.form['SAMLResponse']
    session_info = get_authn_response(current_app.config, session, xmlstr)
    logger.debug('Trying to locate the user authenticated by the IdP')

    user = authenticate(current_app, session_info)
    if user is None:
        logger.error('Could not find the user identified by the IdP')
        raise HTTPUnauthorized("Access not authorized")

    action = get_action()
    return action(session_info, user)