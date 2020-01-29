# coding: utf-8

"""
Common test functionality for backends.
"""

import pytest

from keyring.tests.test_backend import BackendBasicTests

__metaclass__ = type


# override the fixture.
# https://stackoverflow.com/questions/56163688/how-to-override-a-pytest-fixture-calling-the-original-in-pytest-4
class BackendFileTests(BackendBasicTests):

    @pytest.fixture(autouse=True)
    def _init_properties(self, request):
        self.keyring = self.init_keyring()
        self.credentials_created = set()
        yield

    @pytest.fixture(autouse=True)
    def _cleanup_me(self):
        yield
        for item in self.credentials_created:
            self.keyring.delete_password(*item)

    def setUp(self):
        pass

    def tearDown(self):
        pass
