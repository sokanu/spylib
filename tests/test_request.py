from __future__ import absolute_import
import unittest


class TestRequest(unittest.TestCase):
    def test_init_with_good_access_token_success(self):
        """
        Given:
            - a good access token
            - a base url
            - a secret
            - an algorithm
        When:
            - a request object is built.
        Outcome:
            - all fields are set except refresh token.
        """
        pass

    def test_init_with_good_access_and_refresh_token_success(self):
        """
        Given:
            - a good access and refresh token
            - a base url
            - a secret
            - an algorithm.
        When:
            - a request object is built
        Outcome:
            - all fields are set.
        """

    def test_init_with_bad_access_no_refresh_token_throws_exception(self):
        """
        Given:
            - a bad access token
            - a base url
            - a secret
            - an algorithm
            - no refresh token.
        When:
            - a request object is built.
        Outcome:
            - throws a RefreshException
        """
        pass

    def test_init_with_good_access_no_refresh_token_throws_exception(self):
        """
        Given:
            - a bad access token
            - a base url
            - a secret
            - an algorithm
            - no refresh token.
        When:
            - a request object is built.
        Outcome:
            - throws a RefreshException
        """
        pass
