# LibRustySigs

Author: Silene0259

Organization: LithiumSource

## Description

It offers rusty signatures to validate crates.

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
