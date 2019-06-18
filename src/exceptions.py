from __future__ import absolute_import
import logging


class LoginException(Exception):
    logging.debug("Login failed for an internal service request.")


class RefreshException(Exception):
    logging.debug("Refresh of access token failed for an internal service request.")


class MethodException(Exception):
    logging.debug("An invalid method was passed to the requests library.")
