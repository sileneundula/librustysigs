# LibRustySigs

[![Crates.io Version](https://img.shields.io/crates/v/librustysigs)](https://crates.io/crates/librustysigs)
![Crates.io License](https://img.shields.io/crates/l/librustysigs)
![Deps.rs Crate Dependencies (latest)](https://img.shields.io/deps-rs/librustysigs/latest)
![Crates.io Total Downloads](https://img.shields.io/crates/d/librustysigs)


## Description

**RustySignatures** offers high-security, post-quantum digital signature schemes with hedged signatures with easy to use API. It uses the algorithms:

- [X] ShulginSigning (SPHINCS+ Level 5 & ED25519 with hedged signatures)
    - [X] Benefits:
        - [X] Offers Post-Quantum based on Hash-Algorithms and Classical Digital Signature Security based on Elliptic Curves with randomized security.
        - [X] Offers Hedged Signatures, a more secure way of thwarting attacks on both SPHINCS+ and ED25519 signatures.
        - [X] Offers Nonce Input of Ephermal Passwords for better CSPRNG
        - [X] Offers Serialization, Zeroiziation, and other security features.
        - [X] Offers Certificate Creation
        - [X] Offers Easy To Use Public Key using both public keys delimited by a colon.
        - [X] Contains a RustySignature Struct for simple verification.
        - [X] ID_8 and Fingerprint
    - [X] Purpose:
        - [X] Long-Term Security and High Security Environments
        - [X] Digital Integrity
        - [X] Small Public Keys / Small Private Keys
        - [X] Slower Speed at Verification and Signing than most, offering more security and being better suited for long-term security/digital integrity.
    - [X] Key Size:
        - [X] Public Keys
            - [X] SPHINCS+: 64 bytes, or 128 hexadecimal characters
            - [X] ED25519: 32 bytes, or 64 hexadecimal characters.
        - [X] Private Keys:
            - [X] SPHINCS+: 128 bytes, or 256 hexadecimal characters
            - [X] ED25519: 32-64 bytes, or 64-128 hexadecimal character
        - [X] Signatures:
            - [X] SPHINCS+: ~29_000 bytes (signature can be hashed and stored by hash if need be)
            - [X] ED25519: 64 bytes, or 128 hexadecimal characters.
- [ ] AnneSigning (Dilithium Level 3 + ED25519)
- [ ] PedraSigning (FALCON512/FALCON1024 + ED448)

### Certificate System

It offers a certificate system for trust based design with a multitude of different Public Key Infrastructures (PKIs).

- [X] \[X59] Public Key Infrastructures
    - [X] SelfSigned
    - [ ] Web of Trust
    - [ ] Certificate Authority
    - [ ] X59 (propiertary)
    - [ ] Smart Contracts / Blockchain

### RustyFunds

Decentralized Funding Source (DFS) for Rust Projects implemented by Certificate Verification.

## RFCS

### 1. Design of RustyCerts

The design of RustyCerts contains the following:

- A Keypair (ShulginSigning)
- A Certificate Request (Rusty-CertReq)

It uses the hash function:

- **Finerprint:** BLAKE2B(48 or 384 bits) and SHA3-224
- **ID:** BLAKE2s(8 bytes)

## Contributors

Contributions are welcome :)

## LICENSE

APACHE 2.0
