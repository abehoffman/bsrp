import hashlib
import os
from typing import Any

from .constants import SRP_GENERATOR, SRP_PRIME

BYTE_ORDER = "big"


class SafetyException(Exception):
    """
    Raised if SRP-6a safety checks fail
    """
    pass


def _get_srp_prime() -> int:

    return int(SRP_PRIME, 16)


def _get_srp_generator() -> int:

    return int(SRP_GENERATOR, 16)


def _generate_random_bytes(length: int) -> bytes:
    """
    Cryptographically random bytes
    """

    return os.urandom(length)


def _to_bytes(obj: Any) -> bytes:
    """
    Convert obj to bytes.

    Args:
        obj (int, str, bytes): the object to convert
    Returns:
        bytes representation of the object
    """
    if type(obj) == bytes:
        return obj
    elif type(obj) == int:
        return obj.to_bytes((obj.bit_length() + 7) // 8, byteorder=BYTE_ORDER)
    elif type(obj) == str:
        return bytes(obj, "utf-8")
    else:
        raise Exception("Unable to convert object to bytes.")


def _to_int(obj: Any) -> int:
    """
    Convert obj to integer.

    Args:
        obj (int, str, bytes): the object to convert
    Returns
        integer representation of the object
    """
    if type(obj) == int:
        return obj
    elif type(obj) == bytes:
        return int.from_bytes(obj, byteorder=BYTE_ORDER)
    elif type(obj) == str:
        return int(obj, 16)
    else:
        raise Exception("Unable to convert object to integer.")


def _pad(obj: Any, length: int) -> bytes:
    """
    Left pad byte-string representation of number.

    Args:
        obj (int, str, bytes): the object to pad
        length          (int): the bitlength to pad to
    Returns:
        padded        (bytes): the padded object
    """
    unpadded = _to_bytes(obj)

    return b'\x00' * ((length + 7) // 8 - len(unpadded)) + unpadded


def _Hash(*args) -> bytes:
    """
    Hash of concatenated argument objects.

    Args:
        arg  (int, str, bytes): args to hash
    Returns:
        hash           (bytes): the hash
    """
    hsh = hashlib.sha256()

    for arg in args:
        hsh.update(arg if type(arg) == bytes else _to_bytes(arg))
    return hsh.digest()


def _calculate_x(salt: bytes, identity: str, password: str) -> int:
    """
    Calculate the user secret parameter x.

    Args:
        salt     (bytes): the salt associated with the identity
        identity   (str): the identity
        password   (str): the password
    Returns:
        x          (int): the user secret parameter x
    """
    pre_salt = _Hash(identity, ":", password)
    post_salt = _Hash(salt, pre_salt)

    return int.from_bytes(post_salt, byteorder=BYTE_ORDER)


def _calculate_M(
    generator: int,
    prime: int,
    identity: str,
    salt: bytes,
    A: int,
    B: int,
    session_key: bytes,
) -> bytes:
    """
    Calculate evidence message M hash.

    Args:
        generator     (int): the generator of the prime
        prime         (int): the large safe prime
        identity      (str): the identity
        salt        (bytes): the salt
        A             (int): the public value A from the client
        B             (int): the public value B from the server
        session_key (bytes): the strong session key, individually computed
    Returns:
        message M   (bytes): the message shared by the client to the server
    """
    H_generator = _Hash(generator)
    H_prime = _Hash(prime)
    H_identity = _Hash(identity)
    H_xor = bytes(map(lambda i: i[0] ^ i[1], zip(H_generator, H_prime))) # noqa: W1636; pylint: disable=map-builtin-not-iterating
    return _Hash(H_xor, H_identity, salt, A, B, session_key)
