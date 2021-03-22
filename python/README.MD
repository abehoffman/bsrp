# bsrp

`bsrp` is a python implementation of the secure remote password protocol (SRP-6a).
This library enables a login flow in which the server provides the public value
B before the client reveals its own public value A. This enables a little bit
cleaner of a login flow. This library is designed for server-side use, with a mock
client side library included for testing and reference for frontend use. `bsrp`
has a sister library with the same name implemented in javascript [here]().

## Usage

The following example (taken from the test suite) showcases the flow of data
between the client and the server to achieve login authentication.

```python
from bsrp.client import (
    generate_a_pair,
    process_challenge,
    verify_session as client_verify_session,
)
from bsrp.server import (
    generate_b_pair,
    generate_salt_and_verifier,
    verify_session as server_verify_session,
)

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
```

## Functions

#### Utils

`SafetyException`: Raised if SRP-6a safety checks fail

`_get_srp_prime()`: Returns integer value of the 2048-bit SRP prime

> Note: you may set your own prime by overriding this method

`_get_srp_generator()`: Returns integer value of the generator used to generate the SRP prime

`_generate_random_bytes(length: int)`: Returns cryptographically random bytes

`_to_bytes(obj: Any)`: Converts object to bytes

`_to_int(obj: Any)`: Converts object to integer

`_pad(obj: Any, length: int)`: Returns left padded byte-string representation of number

`_Hash(*args)`: Returns hash of concatenated argument objects

`_calculate_x(salt: bytes, identity: str, password: str)`: Returns the calculated
user secret parameter x

`_calculate_M(generator: int, prime: int, identity: str, salt: bytes, A: int, B: int, session_key: bytes)`: Returns the calculated evidence message M

#### Server

`MessageException`: raised when the message from the client does not match.

`generate_salt_and_verifier(identity: str, password: str)` Returns a tuple of the
salt and verification key

`generate_b_pair(verifier: int)`: Returns private ephemeral b for later use and
public value B for the client

`verify_session(identity: str, salt: bytes, verifier: int, A: int, b: int,M_client: bytes)`: Returns None if session is invalid, evidence key if message
from client is valid

#### Client

`EvidenceException`: raised when server evidence key does not match

`generate_a_pair()`: Returns tuple of private ephemeral a and public value A

`process_challenge(identity: str, password: str, salt: bytes, a: int, A: int, B: int)`: Returns tuple of message and private strong session key

`verify_session(A: int, M: bytes, session_key: bytes, server_H_AMK: bytes)`:
Returns None if session is invalid, evidence key if the server was mutually
authenticated
