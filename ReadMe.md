# SRP Protocol - Secure Remote Password Protocol

## Zero Knowledge Proof - Challange Response Mechanism

### Introduction

SRP protocl performs secure remote authentication for short human-memorizable passwords and resists both active and passive network attacks. It is open-source and most widely standardized protocol which results in being used by both large and small organization. Server using SRP contains verifier for each user which allows to authenticate a client however, if compromised would not allow the attacker to impersonate client.

Stanford HomePage for SRP: <http://srp.stanford.edu/>

### How it works

Following is the list of variables used for implementing SRP-6 and SRP-6a.

```text
    N       A large safe prime (N = 2q+1, where q is prime)
            All arithmetic is done modulo N.
    g       A generator modulo N
    k       Multiplier parameter (k = H(N, g) in SRP-6a, k = 3 for legacy SRP-6)
    s       User's salt
    I       Username
    p       Cleartext Password
    H()     One-way hash function
    ^       (Modular) Exponentiation
    u       Random scrambling parameter
    a, b    Secret ephemeral values
    A, B    Public ephemeral values
    x       Private key (derived from p and s)
    v       Password verifier
```

As a setup phase, it is required to share the plain-text password with the server to register user. This phase is not covered under SRP protocol and must be done once. On the server side, the password is not stored however, 3 key elements are stored which are **Username - Id, Salt and Verifier - v**.

During the registration phase,

- User will share username and password with the server.
- Server will generate a large random integer as a salt.
- Server will use the following method to generate verifier v,

  ```text
  x = H(salt || password)     // Salt is chosen randomly
  v = g^x mod N               // Verifier is computed.
  ```

- Server will store `<Id, salt, v>` in the database for future use.

Now the authentication protocol is as follows,

```text
Client -> Server:  Id, A = g^a              // identifies self, a = random number
Server -> Client:  s, B = kv + g^b          // sends salt, b = random number

    Both:  u = H(A, B)

    Client:  x = H(s, p)                    // user enters password
    Client:  S = (B - kv) ^ (a + ux)        // computes session key
    Client:  K = H(S)

    Server:  S = (Av^u) ^ b                 // computes session key
    Server:  K = H(S)
```

After the above exchange, both the parties should have a shared a strong session key `K`. To complete the authentication, they need to prove each other that their keys match. Although there are multiple ways that this can be acheived, one of the ways is listed as follows,

```text
Client -> Server:  M = H(H(N) xor H(g), H(I), s, A, B, K)
Server -> Client:  H(A, M, K)
```

However, it is to be kept in mind that server will initiate the key verification process.

### Benefits

1. **Security** - Designed to be resistant againts active and passive network attacks.
2. **Privacy** - Never stores client's password.
3. **Forward Secracy** - Even if credentails at server are compromised, it will not allow the attacker to impersonate the client.

### Code

This implementation consists of three main components. The `SRP_Utility` class provides utility functions with default values and contains commonly used methods. The `SRP_Server` class represents the server side of the SRP protocol, while the `SRP_Client` class represents the client side. The `Test` class includes code to demonstrate the functionality of the SRP protocol.

To run the code, ensure that Java is installed on your local machine and execute the following command to run the `Test` class:

```bash
java Test.java
```

To test with custom values, modify the variable values as needed. Keep in mind that the computed sessionKey will match at both ends for each execution, but it will differ from previous runs since the private and public values are randomly generated each time.

### Note

This repository serves as a demonstration and basic implementation of the SRP-6a protocol, intended solely for reference and educational purposes. It is not meant for commercial or personal use and may contain undetected bugs.
