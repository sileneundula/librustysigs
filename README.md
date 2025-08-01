# LibRustySigs

[![Crates.io Version](https://img.shields.io/crates/v/librustysigs)](https://crates.io/crates/librustysigs)
![Crates.io License](https://img.shields.io/crates/l/librustysigs)
![Deps.rs Crate Dependencies (latest)](https://img.shields.io/deps-rs/librustysigs/latest)
![Crates.io Total Downloads](https://img.shields.io/crates/d/librustysigs)


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
