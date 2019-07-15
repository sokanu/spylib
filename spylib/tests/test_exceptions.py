from __future__ import absolute_import
from ..exceptions import (
    APIException,
    BadRequest,
    NotAuthenticated,
    PermissionDenied,
    NotFound,
    MethodNotAllowed,
    ServiceUnavailable,
)
import unittest


class ExceptionTestCase(unittest.TestCase):
    _cls = APIException
    kwargs = None

    def test_init(self):
        kwargs = self.kwargs or {}
        exception = self._cls(**kwargs)

        assert exception.message == self._cls.default_message.format(**kwargs)
        assert exception.errors == self._cls.default_errors

    def test_raises_with_no_params(self):
        with self.assertRaises(self._cls):
            raise self._cls(**(self.kwargs or {}))

    def test_raises_with_message(self):
        message = "There's a snake in my boots!"

        with self.assertRaises(self._cls) as e:
            raise self._cls(message=message, **(self.kwargs or {}))

        assert e.exception.message == message

    def test_raises_with_message_and_errors(self):
        message = "Somebody poisoned the water hole!"
        errors = ["It was definitely buzz"]

        with self.assertRaises(self._cls) as e:
            raise self._cls(message=message, errors=errors, **(self.kwargs or {}))

        assert e.exception.message == message
        assert e.exception.errors == errors


class BadRequestTestCase(ExceptionTestCase):
    _cls = BadRequest


class NotAuthenticatedTestCase(ExceptionTestCase):
    _cls = NotAuthenticated


class PermissionDeniedTestCase(ExceptionTestCase):
    _cls = PermissionDenied


class NotFoundTestCase(ExceptionTestCase):
    _cls = NotFound


class MethodNotAllowedTestCase(ExceptionTestCase):
    _cls = MethodNotAllowed
    kwargs = {"method": "DELETE"}


class ServiceUnavailableTestCase(ExceptionTestCase):
    _cls = ServiceUnavailable
    kwargs = {"code": 500}
