from __future__ import absolute_import
from jwt import decode
from jwt import DecodeError
from jwt import ExpiredSignatureError


def has_permission(jwt, uuid, permission, JWT_ALGORITHM, JWT_SECRET):
    try:
        decoded = decode(jwt, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        services = decoded.get("services", None)
        if services is None:
            return False
        return permission in services[uuid]
    except (DecodeError, KeyError, Exception, ExpiredSignatureError) as e:
        raise e
