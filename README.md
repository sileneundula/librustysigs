# LibRustySigs

Author: Joseph P Tortorelli (Silene0259)

Organization: YugenSource | LithiumSource

## Description

It offers rusty signatures to validate crates.

## RFCS

### 1. Design of RustyCerts

The design of RustyCerts contains the following:

- A Certificate Request (Rusty-CertReq)
- A Keypair (ShulginSigning)

It uses the hash function:

- **Finerprint:** BLAKE2B(48 or 384 bits)
- **ID:** BLAKE2B(8 bytes)

## LICENSE

APACHE 2.0
