//! # Registry
//! 
//! - Contains public keys
//!     - ED25519 (32-bytes)
//!     - SPHINCS+ (64-bytes)
//! - Ephermal Hash of the public keys and signatures (8-bytes)
//! - Finerprint of the public keys (Blake2b(48))
//! - ID: Registry ID
//! 
//! ## Notes
//! 
//! we take in the UserCertificate then need to get its static PublicKeyID using BLAKE2B(48) or BLAKE2B(64). Maybe even BLAKE2s(32)
//! 
//! ## TODO
//! 
//! - [ ] Certificate Signing Request
//!     - [ ] Web of Trust
//!     - [ ] CA
//!     - [ ] Server (Registry)
//! 
//! - [ ] Certificate Revocation Service
//!     - [ ] Domain
//! 
//! - [ ] Certificate Actions
//!     - [ ] Domain
//!     - [ ] Peer-2-Peer
//!     - [ ] Trust
//!     - [ ] Analysis for Web of Trust
//! 
//! 
//! Look between usage of HashMaps vs HashSet for the proposed problem

use libslug::slugcrypt::internals::signature::ed25519::ED25519SecretKey;
use libslug::slugcrypt::internals::signature::sphincs_plus::SPHINCSSecretKey;
use serde::{Serialize,Deserialize};

use libslug::slugcrypt::internals::signature::{ed25519::ED25519PublicKey, sphincs_plus::SPHINCSPublicKey};
use libslug::slugcrypt::internals::digest::blake2::SlugBlake2bHasher;
use libslug::slugcrypt::internals::digest::digest::SlugDigest;

use std::collections::HashSet;

use chrono::prelude::*;

use zeroize::{Zeroize,ZeroizeOnDrop};

use crate::UserCertificate;

use crate::prelude::*;

// Decentralized Certificates



pub enum AlterCertificateInfo {
    _0x00CREATE_CERTIFICATE,
    _0x01REVOKE_CERTIFICATE,
    _0x02UPDATE_CERTIFICATE,
    _0x03WEBOFTRUST,
    _0x04SIGNCERTIFICATE,
    

    _0xf7EMPTYINVALID,
    _0xf8SIGNKEY,
    _0xf9SIGNDATA,
    _0xfaSIGNSOURCE,
    _0xfbSIGNEPHERMALMESSAGE,
    _0xfcSIGNCERTIFICATE,
    _0xfdSIGNFILE,
    _0xffSIGNEXTENDABLE(u16),
}

/// # CertificateSigningRequest (CSR)
/// 
/// The initial sent signing request from client to server.
/// 
/// Requires Signing of UserCertificate.id
pub struct CertificateSigningRequest {
    _type: CertificateType,
    cert: UserCertificate,
    challenge: Challenge,
}

pub struct Challenge {
    challenge: String,
    reasons: Vec<AlterCertificateInfo>,
}

pub struct CertificateSigningInitialResponse {
    csr: CertificateSigningRequest,
    challenge: String,
    tx_id: String,
}

pub struct UserData {
    email: String,
    author: String,
    other: Vec<(String,String)>
}

pub struct CSR_DOMAIN {
    top_level: String,
    name: String,
    subdomains: Vec<String>,
    namespace: String,
}

pub struct CertificateSigningRequestResponse {
    id: u64,
    _type: CertificateType,
    cert_domain: CSR_DOMAIN,
}

pub enum CertificateType {
    SelfSigned,
    CertificateAuthority,
    Intermediate,
    WOT,
    Security,
}

type PublicKeyID = String;

// Public Key Cache
type ED25519PublicKeyCache = String; // 64
type SPHINCSPublicKeyCache = String; // 64

// Ephermal Signatures ID
type EphermalSignatureID = String; // 8-bytes


/// # RustySigsRegistry
/// 
/// Certificate Repository using **PublicKeyID** (BLAKE2B(48))
/// 
/// The `PublicKeyID` is defined as the `ED25519 PK` and `SPHINCS+ PK` in hexadecimal with a delimiter of a colon between them, with the ED25519 keypair preceeding the SPHINCS+ keypair.
pub struct RustySigsRegistry {
    certificates: HashSet<PublicKeyID,UserCertificate>
}

pub struct RustySigsRegistryCache {
    id: HashSet<u64, PublicKeyID>,
    ed25519_pk: HashSet<ED25519PublicKeyCache, PublicKeyID>,
    sphincs_pk: HashSet<SPHINCSPublicKeyCache, PublicKeyID>,
    
    ephermal_sig: HashSet<EphermalSignatureID,PublicKeyID>,
}

/// # Certificate Request
/// 
/// The Certificate Request is a way of requesting a certificate to the server.
#[derive(Serialize,Deserialize,Clone)]
pub struct RustySigsCertRequest {
    version: u8, // 0: Alpha, 1: Beta, 2: Release, 3: Extended
    
    common_name: String,
    owners: Vec<String>,
    timestamp: DateTime<Utc>,

    keypair: UserCertificate,
}

/// # RustySigsConnect
/// 
/// Connects through the internet.
pub struct RustySigsConnect;

/// # ShulginSigning
/// 
/// ShulginSigning contains:
/// 
/// - id_hash: 8-bytes (BLAKE2B)
/// - fingerprint: 48-bytes (BLAKE2B)
/// - Public Key (ED25519) | 32 bytes
/// - Public Key (SPHINCS+) | 64 bytes
#[derive(Serialize,Deserialize,Clone,Zeroize,ZeroizeOnDrop)]
pub struct ShulginSigning {
    id_hash: String, // 8-bytes
    fingerprint: String, // 48-bytes

    classical_pk: ED25519PublicKey, // 32-bytes
    sphincs_pk: SPHINCSPublicKey, // 64-bytes
}

impl ShulginSigning {
    /// # New ShulginSigning Cert
    /// 
    /// This contains all needed information for ShulginSigning
    pub fn new(classical_pk: ED25519PublicKey, sphincs_pk: SPHINCSPublicKey) -> Self {
        let hashable_str = Self::format_for_hashing(&classical_pk, &sphincs_pk);
        
        let mut hasher = SlugBlake2bHasher::new(48);
        let blake2b_hash_48 = SlugDigest::from_bytes(&hasher.update(hashable_str.as_bytes())).expect("Failed To Get From Bytes").to_string().to_string();

        let mut hasher_id = SlugBlake2bHasher::new(8);
        let blake2b_id = SlugDigest::from_bytes(&hasher.update(&blake2b_hash_48)).unwrap().to_string().to_string();

        
        return Self {
            id_hash: blake2b_id,
            fingerprint: blake2b_hash_48,

            classical_pk: classical_pk,
            sphincs_pk: sphincs_pk,
        }
    }
    fn format_for_hashing(classical_pk: &ED25519PublicKey, sphincs_pk: &SPHINCSPublicKey) -> String {
        let mut s = String::new();
        
        s.push_str(classical_pk.to_hex_string().as_str());
        s.push_str(":");
        s.push_str(sphincs_pk.to_hex_string().unwrap().as_str());

        return s
    }
    /// Delimiter is `:`
    pub fn get_delimiter() -> String {
        return String::from(":")
    }
}