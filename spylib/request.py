from __future__ import absolute_import
from .exceptions import APIException
from .exceptions import AuthCredentialException
from .exceptions import BadRequest
from .exceptions import MethodException
from .exceptions import MethodNotAllowed
from .exceptions import NotAuthenticated
from .exceptions import NotFound
from .exceptions import PermissionDenied
from .exceptions import ServiceUnavailable
from .settings import AUTH_BASE_URL
from jwt import decode
from jwt import ExpiredSignatureError
from requests import get, delete, post, patch, put
from six.moves.urllib.parse import urljoin


class Observable(object):
    """
    The observable class that tracks observers, and notifies them when a change occurs.
    """

    def __init__(self, observer_lst=None, *args, **kwargs):
        self._observers = []
        if observer_lst and type(observer_lst) == list:
            self._observers = [] + observer_lst

    def register_observer(self, observer):
        self._observers.append(observer)

    def notify_observers(self, *args, **kwargs):
        for obs in self._observers:
            obs.notify(self, *args, **kwargs)


class Observer(object):
    """
    An observer that can be implemented by the consumer in order to ease tracking of changes of access and refresh tokens.
    The observables within ServiceRequestFactory will call `notify` on classes that inherit Observer and implement `notify`.
    """

    def __init__(self, observable=None, *args, **kwargs):
        if observable:
            observable.register_observer(self)

    def notify(self, observable, *args, **kwargs):
        """
        Notify is a method that is triggered on an observer, when an observable changes.
        The `observable` is a type of object that inherits the `Observable` type. For this libraries purpose, ServiceRequestFactory inherits from `Observable` type.
        """
        raise NotImplementedError


class ServiceRequestFactory(Observable):
    """
    A service request factory is an object that is used across our microservices for cross service requests.

    When creating a new instance of the factory, ServiceRequestFactory will eagerly refresh your access token, provided a valid refresh token.
    The factory requires a UUID and API_KEY when being used, as this will act as a fallback in the event your provided tokens fail.
    Storing tokens, and providing configuration is the consumers responsibility when using this library. Fortunately, there are some features provided with spylib that will make this easier.
    When implementing your cross service request, please consider establishing a class that consumes our `Observer` class with a notify functionality. When tokens change in your instance, the observer class will be notified of these changes.
    """

    def __init__(
        self,
        uuid=None,
        api_key=None,
        secret=None,
        algorithm=None,
        access_token=None,
        refresh_token=None,
        *args,
        **kwargs
    ):
        super(ServiceRequestFactory, self).__init__(*args, **kwargs)

        self.uuid = uuid
        self.api_key = api_key
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.secret = secret
        self.algorithm = algorithm

        # Attempt to ensure that the access token is usable
        if self.access_token:
            try:
                decode(self.access_token, self.secret, algorithms=[self.algorithm])
            except ExpiredSignatureError:
                self.fetch_new_tokens()
        else:
            self.fetch_new_tokens()

    def _set_access_token(self, access_token):
        self.access_token = access_token
        self.notify_observers()

    def _set_refresh_token(self, refresh_token):
        self.refresh_token = refresh_token
        self.notify_observers()

    @staticmethod
    def urljoin(base_url, path):
        return urljoin(base_url, path)

    def make_service_request(
        self,
        base_url,
        path,
        method="GET",
        payload=None,
        timeout=2,
        retry_count=0,
        retry_on_401_403=True,
        **kwargs
    ):
        """
        Cross service communication request, with an optional retry mechanism.
        """
        headers = kwargs.get("headers", {})
        if self.access_token:
            headers.update({"Authorization": "Bearer %s" % self.access_token})

        url = ServiceRequestFactory.urljoin(base_url, path)

        if method == "GET":
            resp = get(url, params=payload, headers=headers, timeout=timeout, **kwargs)
        elif method == "DELETE":
            resp = delete(url, headers=headers, timeout=timeout, **kwargs)
        elif method == "POST":
            resp = post(url, json=payload, headers=headers, timeout=timeout, **kwargs)
        elif method == "PATCH":
            resp = patch(url, json=payload, headers=headers, timeout=timeout, **kwargs)
        elif method == "PUT":
            resp = put(url, json=payload, headers=headers, timeout=timeout, **kwargs)
        else:
            raise MethodException

        # Eagerly return on successes
        if resp.status_code in [200, 201]:
            return resp

        # Check for a credential failure - if so, cycle our tokens and try again w/ no retry
        if resp.status_code in [401, 403] and retry_on_401_403:
            self.fetch_new_tokens()
            return self.make_service_request(
                base_url,
                path=path,
                method=method,
                payload=payload,
                timeout=timeout,
                retry_count=retry_count - 1,
                retry_on_401_403=False,
            )

        # Check if we're on the last try, if so, we need to buble an exception
        if retry_count <= 0:
            if resp.status_code == 400:
                raise BadRequest(response=resp)
            elif resp.status_code == 401:
                raise NotAuthenticated(response=resp)
            elif resp.status_code == 403:
                raise PermissionDenied(response=resp)
            elif resp.status_code == 404:
                raise NotFound(response=resp)
            elif resp.status_code == 405:
                raise MethodNotAllowed(method=resp.request.method, response=resp)
            elif resp.status_code >= 500:
                raise ServiceUnavailable(code=resp.status_code, response=resp)
            else:
                raise APIException(response=resp)

        # https://en.wikipedia.org/wiki/List_of_HTTP_status_codes
        RETRIABLE_STATUS_CODES = [500, 501, 502, 503, 504, 507]

        # We can try again... do it.
        if retry_count > 0 and resp.status_code in RETRIABLE_STATUS_CODES:
            return self.make_service_request(
                base_url,
                path=path,
                method=method,
                payload=payload,
                timeout=timeout,
                retry_count=retry_count - 1,
                retry_on_401_403=retry_on_401_403,
            )

        return resp

    def delete(self, base_url, path, timeout=2, retry_count=0, **kwargs):
        return self.make_service_request(
            base_url,
            path=path,
            method="DELETE",
            timeout=timeout,
            retry_count=retry_count,
            **kwargs
        )

    def get(self, base_url, path, payload=None, timeout=2, retry_count=0, **kwargs):
        return self.make_service_request(
            base_url,
            path=path,
            method="GET",
            payload=payload,
            timeout=timeout,
            retry_count=retry_count,
            **kwargs
        )

    def post(self, base_url, path, payload=None, timeout=2, retry_count=0, **kwargs):
        return self.make_service_request(
            base_url,
            path=path,
            method="POST",
            payload=payload,
            timeout=timeout,
            retry_count=retry_count,
            **kwargs
        )

    def patch(self, base_url, path, payload=None, timeout=2, retry_count=0, **kwargs):
        return self.make_service_request(
            base_url,
            path=path,
            method="PATCH",
            payload=payload,
            timeout=timeout,
            retry_count=retry_count,
            **kwargs
        )

    def put(self, base_url, path, payload=None, timeout=2, retry_count=0, **kwargs):
        return self.make_service_request(
            base_url,
            path=path,
            method="PUT",
            payload=payload,
            timeout=timeout,
            retry_count=retry_count,
            **kwargs
        )

    def _fetch_new_access_token_with_refresh_token(self):
        """
        Helper method to use `self.refresh_token` to obtain a new
        access token.

        Sets `self.access_token` if the method succeeds.

        Raises `AuthCredentialException` if it fails.
        """
        if self.refresh_token is None:
            raise AuthCredentialException(
                "Auth refresh failed - no refresh token found"
            )

        # Make a request
        resp = self.post(
            AUTH_BASE_URL,
            "api/v1/tokens",
            cookies={"refresh_token": self.refresh_token},
            retry_on_401_403=False,
            retry_count=1,
        )

        # Validation
        if resp.status_code not in [201]:
            raise AuthCredentialException(
                "Auth refresh failed - auth returned a %d" % resp.status_code
            )

        try:
            access_token = resp.json()["access_token"]
        except (ValueError, KeyError):
            raise AuthCredentialException(
                "Auth refresh failed - failed parsing access token"
            )

        if access_token is None:
            raise AuthCredentialException(
                "Auth refresh failed - failed fetching access token"
            )

        # Persist the token locally
        self._set_access_token(access_token)

    def _fetch_tokens_with_api_key(self):
        """
        Helper method to use `self.uuid` and `self.api_key` to log in to the auth service.

        Sets `self.access_token` and `self.refresh_token` if the method succeeds.

        Raises `AuthCredentialException` if it fails.
        """
        if not self.uuid or not self.api_key:
            raise AuthCredentialException(
                "Auth login failed - attempted to fetch tokens without providing API key or UUID"
            )

        # Make a request
        resp = self.post(
            AUTH_BASE_URL,
            "api/v1/login",
            payload={"uuid": self.uuid, "api_key": self.api_key},
            retry_on_401_403=False,
            retry_count=1,
        )

        # Validation
        if resp.status_code not in [200]:
            raise AuthCredentialException(
                "Auth login failed - service returned a non 200"
            )

        try:
            access_token = resp.json()["access_token"]
        except (ValueError, KeyError):
            raise AuthCredentialException(
                "Auth login failed - Could not parse the access token"
            )

        try:
            refresh_token = resp.cookies["refresh_token"]
        except KeyError:
            raise AuthCredentialException(
                "Auth login failed - fetching the refresh token"
            )

        if access_token is None or refresh_token is None:
            raise AuthCredentialException(
                "Auth login failed - missing either the access token or the refresh token"
            )

        # Persist the access tokens locally
        self._set_access_token(access_token)
        self._set_refresh_token(refresh_token)

    def fetch_new_tokens(self):
        """
        Helper method to obtain new token(s) for making service requests.

        Uses `self.refresh_token` if present, or falls back to using credentials if they are present.
        Currently this only supports `uuid` and `api_key` as a fallback.

        Raises `AuthCredentialException` if there is a problem.
        """
        if self.refresh_token is not None:
            self._fetch_new_access_token_with_refresh_token()
        elif (self.api_key is not None) and (self.uuid is not None):
            self._fetch_tokens_with_api_key()
        else:
            raise AuthCredentialException(
                "Auth token fetch failed - No refresh token or auth credentials were found, login impossible"
            )

    def get_tokens_dict(self):
        return {"access_token": self.access_token, "refresh_token": self.refresh_token}
