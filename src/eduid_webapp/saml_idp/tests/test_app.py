# -*- coding: utf-8 -*-

from __future__ import absolute_import

from eduid_common.api.testing import EduidAPITestCase
from eduid_webapp.saml_idp.app import init_idp_app

__author__ = 'lundberg'


class IdpTests(EduidAPITestCase):
    """Base TestCase for those tests that need a full environment setup"""

    def setUp(self):
        super(IdpTests, self).setUp()

    def load_app(self, config):
        """
        Called from the parent class, so we can provide the appropriate flask
        app for this test case.
        """
        return init_idp_app('testing', config)

    def update_config(self, config):
        return config

    def tearDown(self):
        super(IdpTests, self).tearDown()
        with self.app.app_context():
            self.app.central_userdb._drop_whole_collection()