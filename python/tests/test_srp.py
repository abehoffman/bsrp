import pytest

from bsrp.client import (
    EvidenceException,
    generate_a_pair,
    process_challenge,
    verify_session as client_verify_session,
)
from bsrp.server import (
    MessageException,
    generate_b_pair,
    generate_salt_and_verifier,
    verify_session as server_verify_session,
)
from bsrp.utils import SafetyException


def test_generate_salt_and_verifier():

    salt1, verifier1 = generate_salt_and_verifier("bitcoinlover72@yahoo.com", "test")

    assert salt1
    assert verifier1

    assert type(salt1) == bytes
    assert type(verifier1) == int

    salt2, verifier2 = generate_salt_and_verifier("bitcoinlover72@yahoo.com", "test")

    assert salt2
    assert verifier2

    assert salt1 != salt2
    assert verifier1 != verifier2


def test_login_auth():

    identity = "test"
    password = "#yoloswag"

    # A user is initiated with a set identity and password
    salt, verifier = generate_salt_and_verifier(identity, password)

    # The user initiates the login process by sending the identity
    # to the server. Using the verifier and salt, the server calculates
    # and calculates public value B
    b, B = generate_b_pair(verifier)

    # Using the salt and public value B, the client generates
    # message M to prove to the serve that the password is correct.
    a, A = generate_a_pair()
    M, session_key = process_challenge(identity, password, salt, a, A, B)

    # The server then verifies the session and generates an evidence
    # key H_AMK for the client to use for mutual authentication.
    server_H_AMK = server_verify_session(identity, salt, verifier, A, b, M)

    assert server_H_AMK is not None

    # The client then calculates its own H_AMK to verify the server
    # is legit.
    client_H_AMK = client_verify_session(A, M, session_key, server_H_AMK)

    assert client_H_AMK is not None

    # Authentication success
    assert server_H_AMK == client_H_AMK


def test_login_auth_failed_B_is_zero():

    identity = "test"
    password = "#yoloswag"

    # A user is initiated with a set identity and password
    salt, verifier = generate_salt_and_verifier(identity, password)

    # The user initiates the login process by sending the identity
    # to the server. Using the verifier and salt, the server calculates
    # and calculates public value B
    b, B = generate_b_pair(verifier)

    # Using the salt and public value B, the client generates
    # message M to prove to the serve that the password is correct.
    a, A = generate_a_pair()

    with pytest.raises(SafetyException):
        B=0
        M, session_key = process_challenge(identity, password, salt, a, A, B)



def test_login_auth_failed_A_mod_prime_is_zero():

    identity = "test"
    password = "#yoloswag"

    # A user is initiated with a set identity and password
    salt, verifier = generate_salt_and_verifier(identity, password)

    # The user initiates the login process by sending the identity
    # to the server. Using the verifier and salt, the server calculates
    # and calculates public value B
    b, B = generate_b_pair(verifier)

    # Using the salt and public value B, the client generates
    # message M to prove to the serve that the password is correct.
    a, A = generate_a_pair()
    M, session_key = process_challenge(identity, password, salt, a, A, B)

    # The server then verifies the session and generates an evidence
    # key H_AMK for the client to use for mutual authentication.

    with pytest.raises(SafetyException):
        A = 0
        server_verify_session(identity, salt, verifier, A, b, M)


def test_login_auth_failed_messages_do_not_match():

    identity = "test"
    password = "#yoloswag"

    # A user is initiated with a set identity and password
    salt, verifier = generate_salt_and_verifier(identity, password)

    # The user initiates the login process by sending the identity
    # to the server. Using the verifier and salt, the server calculates
    # and calculates public value B
    b, B = generate_b_pair(verifier)

    # Using the salt and public value B, the client generates
    # message M to prove to the serve that the password is correct.
    a, A = generate_a_pair()
    M, session_key = process_challenge(identity, password, salt, a, A, B)

    # The server then verifies the session and generates an evidence
    # key H_AMK for the client to use for mutual authentication.
    with pytest.raises(MessageException):
        M = "lol".encode("utf-8")
        server_verify_session(
            identity,
            salt,
            verifier,
            A,
            b,
            M,
        )


def test_login_auth_failed_evidence_keys_do_not_match():

    identity = "test"
    password = "#yoloswag"

    # A user is initiated with a set identity and password
    salt, verifier = generate_salt_and_verifier(identity, password)

    # The user initiates the login process by sending the identity
    # to the server. Using the verifier and salt, the server calculates
    # and calculates public value B
    b, B = generate_b_pair(verifier)

    # Using the salt and public value B, the client generates
    # message M to prove to the serve that the password is correct.
    a, A = generate_a_pair()
    M, session_key = process_challenge(identity, password, salt, a, A, B)

    # The server then verifies the session and generates an evidence
    # key H_AMK for the client to use for mutual authentication.
    server_H_AMK = server_verify_session(identity, salt, verifier, A, b, M)

    assert server_H_AMK is not None

    # The client then calculates its own H_AMK to verify the server
    # is legit.
    with pytest.raises(EvidenceException):
        server_H_AMK = "lol".encode("utf-8")
        client_verify_session(A, M, session_key, server_H_AMK)
