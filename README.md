# bsrp
`bsrp` is a Python (backend) and Javascript (frontend) implementation of the secure remote password (SRP) protocol, version 6a.
SRP is a type of password-authenticated key exchange (PAKE) that has a couple of excellent features for authentication.
It is used by 1Password, iCloud, AWS Cognito and more for login authentication.

## Why SRP?
The kind lads over at 1Password provided the following rationale for using SRP:
- authenticate without ever sending a password over the network.
- authenticate without the risk of anyone learning any of your secrets – even if they intercept your communication.
- authenticate both the identity of the client and the server to guarantee that a client isn’t communicating with an impostor server.
- authenticate with more than just a binary “yes” or “no”. You actually end up with an encryption key.

This library provides a seamless solution for implementing SRP with a python/javascript tech stack.
Jump to [Python](https://github.com/abehoffman/bsrp/tree/main/python#readme) documentation.
Jump to [Javascript](https://github.com/abehoffman/bsrp/tree/main/javascript#readme) documentation.


## B First SRP Flow
This implementation of the SRP-6a protocol requires just two API calls:
![image](https://user-images.githubusercontent.com/53541863/111525037-c1809780-8722-11eb-8111-db700a05f1c1.png)


## What is different about B-first?
A B-first implementation of the SRP protocol reveals the public value B to the client before receiving the client's public value A and message. This is slightly different than Tom's [pysrp](https://github.com/cocagne/pysrp), allowing for a different data flow. This flow is optimized for cloud-native APIs.


Jump to [python](https://github.com/abehoffman/bsrp/tree/main/python#readme) documentation.
Jump to [javascript](https://github.com/abehoffman/bsrp/tree/main/javascript#readme) documentation.
