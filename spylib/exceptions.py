from __future__ import absolute_import
import logging


class AuthCredentialException(Exception):
    pass


class MethodException(Exception):
    logging.debug("An invalid method was passed to the requests library.")
