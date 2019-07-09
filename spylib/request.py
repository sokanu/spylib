from __future__ import absolute_import
from builtins import super
from requests import get, delete, post, patch, put
from .exceptions import MethodException, LoginException, RefreshException
from jwt import decode, DecodeError
from jwt.exceptions import ExpiredSignatureError
from six.moves.urllib.parse import urljoin
import os


# Ensure environment variables are set
AUTH_BASE_URL = os.environ.get("SPYLIB_AUTH_BASE_URL", None)
assert AUTH_BASE_URL is not None


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
        uuid,
        api_key=None,
        access_token=None,
        secret=None,
        algorithm=None,
        refresh_token=None,
        *args,
        **kwargs
    ):
        super().__init__(**kwargs)

        # Ensure either the API or the access token must be set
        assert bool(api_key or access_token)
    
        try:
            self.uuid = uuid
            self.api_key = api_key
            self.access_token = access_token
            self.refresh_token = refresh_token
            self.secret = secret
            self.algorithm = algorithm
            if self.access_token:
                decode(access_token, secret, algorithms=[algorithm])
        except ExpiredSignatureError:
            try:
                self.refresh_access_token(refresh_token)
            except RefreshException:
                self.login()
        except (DecodeError, KeyError, Exception) as e:
            raise e
        else:
            if self.access_token is None:
                self.login()

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

        # Check for a credential failure - if so, cycle our tokens and try again w/ no retry
        # Note: We pass a negative retry_count here to prevent an infinite chain
        if resp.status_code in [401] and retry_count >= 0:
            self.fetch_new_tokens()
            second_resp = self.make_service_request(
                base_url,
                path=path,
                method=method,
                payload=payload,
                timeout=timeout,
                retry_count=-1,
            )
            return second_resp
        
        # https://en.wikipedia.org/wiki/List_of_HTTP_status_codes
        RETRIABLE_STATUS_CODES = [500, 501, 502, 503, 504, 507]

        if retry_count > 0 and resp.status_code in RETRIABLE_STATUS_CODES:
            return self.make_service_request(
                base_url,
                path=path,
                method=method,
                payload=payload,
                timeout=timeout,
                retry_count=retry_count - 1,
            )
        
        return resp

    def delete(self, base_url, path, timeout, retry_count, **kwargs):
        return self.make_service_request(
            base_url,
            path=path,
            method="DELETE",
            timeout=timeout,
            retry_count=retry_count,
            **kwargs
        )

    def get(self, base_url, path, payload, timeout, retry_count, **kwargs):
        return self.make_service_request(
            base_url,
            path=path,
            method="GET",
            payload=payload,
            timeout=timeout,
            retry_count=retry_count,
            **kwargs
        )

    def post(self, base_url, path, payload, timeout, retry_count, **kwargs):
        return self.make_service_request(
            base_url,
            path=path,
            method="POST",
            payload=payload,
            timeout=timeout,
            retry_count=retry_count,
            **kwargs
        )

    def patch(self, base_url, path, payload, timeout, retry_count, **kwargs):
        return self.make_service_request(
            base_url,
            path=path,
            method="PATCH",
            payload=payload,
            timeout=timeout,
            retry_count=retry_count,
            **kwargs
        )

    def put(self, base_url, path, payload, timeout, retry_count, **kwargs):
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
            raise AuthCredentialException("Auth refresh failed - no refresh token found")

        # Make a request
        resp = self.post(
            AUTH_BASE_URL,
            "api/v1/tokens",
            timeout=2,
            cookies={
                "refresh_token": self.refresh_token
            }
        )

        # Validation
        if resp.status_code not in [201]:
            raise AuthCredentialException("Auth refresh failed - auth returned a %d" % resp.status_code)
        
        try:
            access_token = resp.json()["access_token"]
        except (ValueError, KeyError):
            raise AuthCredentialException("Auth refresh failed - failed parsing access token")
        
        if access_token is None:
            raise AuthCredentialException("Auth refresh failed - failed fetching access token")
        
        # Persist the token locally
        self._set_access_token(access_token)

    def _fetch_tokens_with_api_key(self):
        """
        Helper method to use `self.uuid` and `self.api_key` to log in to the auth service.

        Sets `self.access_token` and `self.refresh_token` if the method succeeds.

        Raises `AuthCredentialException` if it fails.
        """
        if not self.uuid or not self.api_key:
            raise AuthCredentialException("Auth login failed - attempted to fetch tokens without providing API key or UUID")
        
        # Make a request
        resp = self.post(
            AUTH_BASE_URL,
            "api/v1/login",
            timeout=2,
            payload={
                "uuid": self.uuid,
                "api_key": self.api_key
            }
        )

        # Validation
        if resp.status_code not in [200]:
            raise AuthCredentialException("Auth login failed - service returned a non 200")

        try:
            access_token = resp.json()["access_token"]
        except (ValueError, KeyError):
            raise AuthCredentialException("Auth login failed - Could not parse the access token")

        try:
            refresh_token = resp.cookies["refresh_token"]
        except KeyError:
            raise AuthCredentialException("Auth login failed - fetching the refresh token")

        if access_token is None or refresh_token is None:
            raise AuthCredentialException("Auth login failed - missing either the access token or the refresh token")

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

        # Try to use the refresh token to get a new access token
        if self.refresh_token:
            self._fetch_new_access_token_with_refresh_token()
        else if (self.api_key is not None) and (self.uuid is not None):
            self._fetch_tokens_with_api_key()
        else:
            raise AuthCredentialException('Auth token fetch failed - No refresh token or auth credentials were found, login impossible')

    def get_tokens_dict(self):
        return {"access_token": self.access_token, "refresh_token": self.refresh_token}
