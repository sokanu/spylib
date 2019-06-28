from __future__ import absolute_import
from requests import get, delete, post, patch, put
from .exceptions import MethodException, LoginException, RefreshException
from jwt import decode, DecodeError
from jwt.exceptions import ExpiredSignatureError
from six.moves.urllib.parse import urljoin
import os


class Observable:
    """
    The observable class that tracks observers, and notifies them when a change occurs.
    """

    def __init__(self):
        self._observers = []

    def register_observer(self, observer):
        self._observers.append(observer)

    def notify_observers(self, *args, **kwargs):
        for obs in self._observers:
            obs.notify(self, *args, **kwargs)


class Observer:
    """
    An observer that must be implemented by the consumer.
    The observables within ServiceRequestFactory will call `notify` of the observer.
    """

    def __init__(self, observable):
        observable.register_observer(self)

    def notify(self, observable, *args, **kwargs):
        """
        Notify is a method that is triggered on an observer, when an observable changes.
        The `observable` is a type of object that inherits the `Observable` type. For this libraries purpose, ServiceRequestFactory inherits from `Observable` type.
        """
        raise NotImplementedError


class ServiceRequestFactory(Observable):
    """
    Contains methods for making requests within the sokanu service network.
    """

    def __init__(
        self,
        uuid,
        api_key,
        access_token=None,
        secret=None,
        algorithm=None,
        refresh_token=None,
    ):
        """
        Configures a ServiceRequestFactory object for cross service requests.
        Eagerly refreshes invalid access tokens.
        Falls back on trying to log the entity in if access tokens are unavailable.
        """
        super().__init__()
        try:
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
                self.login(uuid, api_key)
        except (DecodeError, KeyError, Exception) as e:
            raise e
        else:
            if self.access_token is None:
                self.login(uuid, api_key)

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

        UNKNOWN_SERVER_ERROR = 500

        if retry_count > 0 and resp.status_code >= UNKNOWN_SERVER_ERROR:
            return self.make_service_request(
                base_url,
                path=path,
                method=method,
                payload=payload,
                timeout=timeout,
                retry_count=retry_count - 1,
            )
        elif retry_count > 0 and resp.status_code == 401:
            try:
                decode(self.access_token, self.secret, algorithms=[self.algorithm])
            except ExpiredSignatureError:
                if not self.refresh_token:
                    raise ExpiredSignatureError
                self.access_token = self.refresh_access_token(self.refresh_token)
                return self.make_service_request(
                    base_url,
                    path=path,
                    method=method,
                    payload=payload,
                    timeout=timeout,
                    retry_count=retry_count - 1,
                )
        return resp

    def refresh_access_token(self, refresh_token):
        """
        Exchanges a refresh token with auth, and returns the subsequent access token.
        """
        base_url = os.environ.get("SPYLIB_AUTH_BASE_URL", None)
        if not base_url:
            raise Exception("SPYLIB_AUTH_BASE_URL must be set.")
        if not refresh_token:
            raise RefreshException
        cookies = {"refresh_token": refresh_token}
        resp = self.make_service_request(
            base_url,
            "/api/v1/tokens",
            method="POST",
            payload={},
            timeout=2,
            cookies=cookies,
        )
        if resp.status_code != 201:
            raise RefreshException
        access_token = resp.json().get("access_token")
        if not access_token:
            raise RefreshException
        self._set_access_token(access_token)

    def login(self, uuid, api_key):
        """
        Login a user on auth, returns access_token and refresh_token.
        """
        base_url = os.environ.get("SPYLIB_AUTH_BASE_URL", None)
        if not base_url:
            raise Exception("SPYLIB_AUTH_BASE_URL must be set.")
        resp = self.make_service_request(
            base_url,
            "api/v1/login",
            method="POST",
            payload={"api_key": api_key, "uuid": uuid},
        )

        if resp.status_code != 200:
            raise LoginException("Auth service login failed")
        access_token = resp.json().get("access_token")
        refresh_token = resp.cookies["refresh_token"]
        if access_token is None or refresh_token is None:
            raise LoginException
        self._set_access_token(access_token)
        self._set_refresh_token(refresh_token)

    def get_tokens_dict(self):
        return {"access_token": self.access_token, "refresh_token": self.refresh_token}
