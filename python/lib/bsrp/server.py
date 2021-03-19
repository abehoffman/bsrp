from typing import Tuple

from .utils import (
    SafetyException,
    _calculate_M,
    _calculate_x,
    _generate_random_bytes,
    _get_srp_generator,
    _get_srp_prime,
    _Hash,
    _pad,
    _to_int,
)


class MessageException(Exception):
    """
    Exception raised when the message from the client does not match.
    """
    pass


def generate_salt_and_verifier(identity: str, password: str) -> Tuple[bytes, int]:
    """
    Create salt and verification key from identity and password.

    Args:
        identity (str): the identity to generate with
        password (str): the password to generate with
    Returns:
        Tuple(salt (bytes), verifier (int))
    """

    salt = _generate_random_bytes(32)
    generator = _get_srp_generator()
    prime = _get_srp_prime()

    x = _calculate_x(salt, identity, password)

    verifier = pow(generator, x, prime)

    return salt, verifier


def generate_b_pair(verifier: int) -> Tuple[int, int]:
    """
    Generates private ephemeral b for later use and public
    value B for the client.

    Args:
        verifier (int): the verifer to generate the pair with
    Returns:
        Tuple(private b (int), public B (int))
    """
    prime = _get_srp_prime()

    width = prime.bit_length()

    generator = _get_srp_generator()
    padded_generator = _pad(generator, width)

    b = _to_int(_generate_random_bytes(32))  # RFC-5054 recommends 256 bits

    # k - multiplier
    k = _to_int(_Hash(prime, padded_generator))

    # B = (k*verifier + (generator^b) % prime) % prime
    B = (k * verifier + pow(generator, b, prime)) % prime

    return b, B


def verify_session(
        identity: str,
        salt: bytes,
        verifier: int,
        A: int,
        b: int,
        M_client: bytes,
    ) -> bytes:
    """
    After the client has sent public value A and message M,
    the server verifies the session and returns evidence key
    H_AMK back to the client for mutual authentication.

    Args:
        identity   (str): the identity
        salt     (bytes): the salt stored by the server
        verifier   (int): the verifier stored by the server
        A          (int): the public value A from the client
        b          (int): the private ephemeral b stored by the server
        M_client (bytes): the message from the client
    Returns:
        H_AMK    (bytes): the evidence key to prove server legitimacy
    Raises:
        SafetyException: if SRP-6a safety checks fail
        MessageException: if server computed message does not match client message (auth failed)
    """
    prime = _get_srp_prime()

    width = prime.bit_length()

    generator = _get_srp_generator()
    padded_generator = _pad(generator, width)

    # SRP-6a safety check
    if A % prime == 0:
        raise SafetyException("A mod prime is 0. Auth Failed.")

    # k - multiplier
    k = _to_int(_Hash(prime, padded_generator))

    # B = (k*verifier + (generator^b) % prime) % prime
    B = (k * verifier + pow(generator, b, prime)) % prime

    padded_A = _pad(A, width)
    padded_B = _pad(B, width)

    # Precalculate scrambler
    u = _to_int(_Hash(padded_A, padded_B))

    # Calculate shared session key
    # S = (A*(v^u))^b
    S = pow(A * pow(verifier, u, prime), b, prime)
    session_key = _Hash(S)

    # Calculate shared message
    M_server = _calculate_M(
        generator,
        prime,
        identity,
        salt,
        A,
        B,
        session_key
    )

    if M_client != M_server:
        raise MessageException("Messages do not match. Auth Failed.")

    H_AMK = _Hash(A, M_server, session_key)

    return H_AMK
