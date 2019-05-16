# -*- coding: utf-8 -*-
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

DEBUG = False
DEVELOPMENT = DEBUG

# Database URIs
MONGO_URI = ''
REDIS_HOST = ''
REDIS_PORT = 6379
REDIS_DB = 0

# Secret key
SECRET_KEY = 'supersecretkey'

# Logging
LOG_LEVEL = 'DEBUG'

# IdP specific
SYSLOG_DEBUG = '0'              # '1' for True, '0' for False
NUM_THREADS = '8'
LISTEN_ADDR = '0.0.0.0'
LISTEN_PORT = '8088'
PYSAML2_CONFIG = 'idp_conf.py'  # path prepended in IdPConfig.__init__()
FTICKS_SECRET_KEY = None
FTICKS_FORMAT_STRING = 'F-TICKS/SWAMID/2.0#TS={ts}#RP={rp}#AP={ap}#PN={pn}#AM={am}#'
STATIC_DIR = None   # directory for local static files
STATIC_LINK = '#'   # URL to static resources that can be used in templates
SSL_ADAPTER = 'builtin'  # one of cherrypy.wsgiserver.ssl_adapters
SERVER_CERT = None  # SSL cert filename
SERVER_KEY = None   # SSL key filename
CERT_CHAIN = None   # SSL certificate chain filename, or None
USERDB_MONGO_DATABASE = 'eduid_am'  # eduid_am for old userdb, eduid_userdb for new
MONGO_URI = None    # Base mongodb:// URI
SSO_SESSION_MONGO_URI = None   # mongodb:// URI for SSO session cache
SSO_SESSION_LIFETIME = '15'  # Lifetime of SSO session in minutes
RAVEN_DSN = None
CONTENT_PACKAGES = []  # List of Python packages ("name:path") with content resources
VERIFY_REQUEST_SIGNATURES = '0'  # '1' for True, '0' for False
STATUS_TEST_USERNAMES = []
SIGNUP_LINK = '#'          # for login.html
DASHBOARD_LINK = '#'       # for forbidden.html
PASSWORD_RESET_LINK = '#'  # for login.html
DEFAULT_LANGUAGE = 'en'
BASE_URL = None
DEFAULT_EPPN_SCOPE = None
MAX_AUTHN_FAILURES_PER_MONTH = '50'  # Kantara 30-day bad authn limit is 100
LOGIN_STATE_TTL = '5'   # time to complete an IdP login, in minutes
DEFAULT_SCOPED_AFFILIATION = None
VCCS_URL = 'http://localhost:8550/'  # VCCS backend URL
INSECURE_COOKIES = '0'  # Set to 1 to not set HTTP Cookie 'secure' flag
ACTIONS_APP_URI = 'http://actions.example.com/'
TOU_VERSION = 'version1'
REDIS_SENTINEL_HOSTS = []
REDIS_SENTINEL_SERVICE_NAME = None
REDIS_HOST = None
REDIS_PORT = '6379'
REDIS_DB = '0'
SESSION_APP_KEY = None
