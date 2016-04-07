# -*- coding: utf-8 -*-

from __future__ import absolute_import


__author__ = 'lundberg'

"""
For more built in configuration options see,
http://flask.pocoo.org/docs/0.10/config/#builtin-configuration-values
"""

DEBUG = False

# Database URIs
MONGO_URI = 'mongodb://'
REDIS_HOST = ''
REDIS_PORT = 6379
REDIS_DB = 0

# Secret key
SECRET_KEY = None

# Logging
LOG_FILE = None
LOG_LEVEL = 'INFO'

# Session
PERMANENT_SESSION_LIFETIME = 300  # I have no clue what is a good value

# OIDC
PROVIDER_CONFIGURATION_INFO = {}
CLIENT_REGISTRATION_INFO = {}
USERINFO_ENDPOINT_METHOD = 'POST'

# Api Spec config - https://github.com/OAI/OpenAPI-Specification
# from apispec import APISpec
# APISPEC_SPEC = APISpec(
#    title = 'eduid-idproofing-letter',
#    version = 'v1',
#    plugins = ('apispec.ext.marshmallow',),
# )

APISPEC_SPEC = None
APISPEC_SWAGGER_URL = '/swagger/'
APISPEC_SWAGGER_UI_URL = '/swagger-ui/'