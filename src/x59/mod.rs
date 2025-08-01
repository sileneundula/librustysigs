//! # X59 PKI
//! 
//! The X59 PKI is a useful, secure, code-signing public key infrastructure for the future. It is post-quantum and contains security that will last a long time.
//! 
//! [] X59
//!     [] Web of Trust
//!     [] X509
//!     [] Blockchain
//!     [] Keybase-Inspired Components







pub struct X59Authority {
    x59type: X59Type,
    
    signer: String,
    signature: String,
}

pub enum X59Type {
    RootAuthority,
    Authority,
    Intermediate,
    Cert,
}

pub enum X59PKIStyle {
    WOT,
    X509,
    Blockchain,
}