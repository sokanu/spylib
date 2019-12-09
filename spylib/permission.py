"""Permissions file for Spylib."""
from __future__ import absolute_import
from jwt import decode
from jwt import DecodeError
from jwt import ExpiredSignatureError


def has_permission(jwt, uuid, permission, JWT_ALGORITHM, JWT_SECRET):
    """
    Permission check on JWT for a given uuid.

    Args:
        jwt(str): A JSON Web Token that is deciphered and checked.
        uuid(str): The UUID that is checked for a given permission.
        permission(str): The permission that is checked to exist on the given uuid.
        JWT_ALGORITHM(str): The algorithm used for encoding and decoding the jwt.
        JWT_SECRET(str): The secret used for encoding and decoding the jwt.
    """
    try:
        decoded = decode(jwt, JWT_SECRET, algorithms=[JWT_ALGORITHM])
        services = decoded.get("services", None)
        if services is None:
            return False
        if not services.get(uuid, None):
            return False
        return permission in services[uuid]
    except (DecodeError, KeyError, Exception, ExpiredSignatureError) as e:
        raise e
