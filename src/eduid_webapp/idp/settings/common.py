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

# The Redis host to use for session storage.
REDIS_HOST = None

# The port of the Redis server (integer).
REDIS_PORT = '6379'

# The Redis database number (integer).
REDIS_DB = '0'

# Redis sentinel hosts, comma separated
REDIS_SENTINEL_HOSTS = ''

# The Redis sentinel 'service name'.
REDIS_SENTINEL_SERVICE_NAME = None

# The Redis session encrypted application key.
SESSION_APP_KEY = None

# Secret key
SECRET_KEY = None

# Logging
LOG_LEVEL = 'DEBUG'

# IdP specific
SYSLOG_DEBUG = '0'              # '1' for True, '0' for False

# Number of worker threads to start (integer).
# EduID IdP spawns multiple threads to make use of all CPU cores in the password
# pre-hash function.
# Number of threads should probably be about 2x number of cores to 4x number of
# cores (if hyperthreading is available).
NUM_THREADS = '8'

# IP address to listen on.
LISTEN_ADDR = '0.0.0.0'

# The port the IdP authentication should listen on (integer).
LISTEN_PORT = '8088'

# pysaml2 configuration file. Separate config file with SAML related parameters.
PYSAML2_CONFIG = 'idp_conf.py'  # path prepended in IdPConfig.__init__()

# SAML F-TICKS user anonymization key. If this is set, the IdP will log FTICKS data
# on every login.
FTICKS_SECRET_KEY = None

# Get SAML F-TICKS format string.
FTICKS_FORMAT_STRING = 'F-TICKS/SWAMID/2.0#TS={ts}#RP={rp}#AP={ap}#PN={pn}#AM={am}#'

# Directory with static files to be served.
STATIC_DIR = None   # directory for local static files
STATIC_LINK = '#'   # URL to static resources that can be used in templates

# CherryPy SSL adapter class to use (must be one of cherrypy.wsgiserver.ssl_adapters)
SSL_ADAPTER = 'builtin'  # one of cherrypy.wsgiserver.ssl_adapters

# SSL certificate filename (None == SSL disabled)
SERVER_CERT = None  # SSL cert filename

# SSL private key filename (None == SSL disabled)
SERVER_KEY = None   # SSL key filename

# SSL certificate chain filename
CERT_CHAIN = None   # SSL certificate chain filename, or None

#  UserDB database name.
USERDB_MONGO_DATABASE = 'eduid_am'  # eduid_am for old userdb, eduid_userdb for new

# MongoDB connection URI (string). See MongoDB documentation for details.
MONGO_URI = None    # Base mongodb:// URI

# MongoDB connection URI (string) for PySAML2 SSO sessions.
SSO_SESSION_MONGO_URI = None   # mongodb:// URI for SSO session cache

# Lifetime of SSO session (in minutes).
# If a user has an active SSO session, they will get SAML assertions made
# without having to authenticate again (unless SP requires it through
# ForceAuthn).
# The total time a user can access a particular SP would therefor be
# this value, plus the pysaml2 lifetime of the assertion.
SSO_SESSION_LIFETIME = '15'  # Lifetime of SSO session in minutes

# Raven DSN (string) for logging exceptions to Sentry.
RAVEN_DSN = None

# Get list of tuples with packages and paths to content resources, such as login.html.
# The expected format in the INI file is
#     content_packages = pkg1:some/path/, pkg2:foo
CONTENT_PACKAGES = []  # List of Python packages ("name:path") with content resources

# Verify request signatures, if they exist.
# This defaults to False since it is a trivial DoS to consume all the IdP:s
# CPU resources if this is set to True.
VERIFY_REQUEST_SIGNATURES = '0'  # '1' for True, '0' for False

# Get list of usernames valid for use with the /status URL.
# If this list is ['*'], all usernames are allowed for /status.
STATUS_TEST_USERNAMES = []

# URL (string) for use in simple templating of login.html.
SIGNUP_LINK = '#'          # for login.html

# URL (string) for use in simple templating of forbidden.html.
DASHBOARD_LINK = '#'       # for forbidden.html

# URL (string) for use in simple templating of login.html.
PASSWORD_RESET_LINK = '#'  # for login.html

# More links
TECHNICIANS_LINK = '#'
STAFF_LINK = '#'
FAQ_LINK = '#'

# URL to static resources that can be used in eduid-IdP-html templates.
STATIC_LINK = '#'

# Default language code to use when looking for web pages ('en').
DEFAULT_LANGUAGE = 'en'

# Base URL of the IdP. The default base URL is constructed from the
# Request URI, but for example if there is a load balancer/SSL
# terminator in front of the IdP it might be required to specify
# the URL of the service.
BASE_URL = None

# The scope to append to any unscoped eduPersonPrincipalName
# attributes found on users in the userdb.
DEFAULT_EPPN_SCOPE = None

# Disallow login for a user after N failures in a given month.
# This is said to be an imminent Kantara requirement.
MAX_AUTHN_FAILURES_PER_MONTH = '50'  # Kantara 30-day bad authn limit is 100

# Lifetime of state kept in IdP login phase.
# This is the time, in minutes, a user has to complete the login phase.
# After this time, login cannot complete because the SAMLRequest, RelayState
# and possibly other needed information will be forgotten.
LOGIN_STATE_TTL = '5'   # time to complete an IdP login, in minutes

# Add a default eduPersonScopedAffiliation if none is returned from the
# attribute manager.
DEFAULT_SCOPED_AFFILIATION = None

# URL to use with VCCS client. BCP is to have an nginx or similar on
# localhost that will proxy requests to a currently available backend
# using TLS.
VCCS_URL = 'http://localhost:8550/'  # VCCS backend URL

# Set to True to NOT set HTTP Cookie 'secure' flag (boolean).
INSECURE_COOKIES = '0'  # Set to 1 to not set HTTP Cookie 'secure' flag

# URI of the actions app.
ACTIONS_APP_URI = 'http://actions.example.com/'

# The plugins for pre-authentication actions that need to be loaded
ACTION_PLUGINS = ''

# The current version of the terms of use agreement.
TOU_VERSION = 'version1'

# Name of cookie used to persist session information in the users browser.
SHARED_SESSION_COOKIE_NAME = 'sessid'

# Key to decrypt shared sessions.
SHARED_SESSION_SECRET_KEY = None

# TTL for shared sessions.
SHARED_SESSION_TTL = '300'
