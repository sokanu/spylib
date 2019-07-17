from __future__ import absolute_import


class AuthCredentialException(Exception):
    pass


class MethodException(Exception):
    pass


class APIException(Exception):
    default_message = "An API call has failed."
    default_errors = None

    def __init__(self, message=None, errors=None, response=None):
        setattr(self, "message", message or self.default_message)
        setattr(self, "errors", errors or self.default_errors)
        setattr(self, "response", response)

    def __str__(self):
        return str(self.message)


class BadRequest(APIException):
    default_message = "Your request is malformed - 400."
    default_errors = None


class NotAuthenticated(APIException):
    default_message = "You are not authenticated - 401."
    default_errors = None


class PermissionDenied(APIException):
    default_message = "You are not authorized to access this resource - 403."
    default_errors = None


class NotFound(APIException):
    default_message = "The resource you requested could not be found - 404."
    default_errors = None


class MethodNotAllowed(APIException):
    default_message = "Method {method} not allowed - 404."
    default_errors = None

    def __init__(self, method, message=None, errors=None, response=None):
        if message is None:
            message = self.default_message.format(method=method)

        super(MethodNotAllowed, self).__init__(
            message=message, errors=errors, response=response
        )


class ServiceUnavailable(APIException):
    default_message = "The service you are trying to reach is unavailable - {code}."
    default_errors = None

    def __init__(self, code, message=None, errors=None, response=None):
        if message is None:
            message = self.default_message.format(code=code)

        super(ServiceUnavailable, self).__init__(
            message=message, errors=errors, response=response
        )
