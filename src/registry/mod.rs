//! # Registry
//! 
//! - Contains public keys (32 + 64 bytes)
//! - Hash of the public keys (8-bytes)
//! - Finerprint of the public keys (Blake2b(48))
//! - ID: Registry ID

use libslug::slugcrypt::internals::signature::ed25519::ED25519SecretKey;
use libslug::slugcrypt::internals::signature::sphincs_plus::SPHINCSSecretKey;
use serde::{Serialize,Deserialize};

use libslug::slugcrypt::internals::signature::{ed25519::ED25519PublicKey, sphincs_plus::SPHINCSPublicKey};
use libslug::slugcrypt::internals::digest::blake2::SlugBlake2bHasher;
use libslug::slugcrypt::internals::digest::digest::SlugDigest;

use chrono::prelude::*;

pub struct RustySigsRegistry {

}

#[derive(Serialize,Deserialize,Clone)]
pub struct RustySigsCertRequest {
    version: u8, // 0: Alpha, 1: Beta, 2: Release, 3: Extended
    common_name: String,
    owners: Vec<String>,
    //timestamp: Date<Utc>,

    keypair: ShulginSigning,
}

/// # RustySigsConnect
/// 
/// Connects through the internet.
pub struct RustySigsConnect;

/// # ShulginSigning
#[derive(Serialize,Deserialize,Clone)]
pub struct ShulginSigning {
    id_hash: String, // 8-bytes
    fingerprint: String, // 48-bytes

    classical_pk: ED25519PublicKey, // 32-bytes
    sphincs_pk: SPHINCSPublicKey, // 64-bytes
}

impl ShulginSigning {
    pub fn new(classical_pk: ED25519PublicKey, sphincs_pk: SPHINCSPublicKey) -> Self {
        let hashable_str = Self::format_for_hashing(&classical_pk, &sphincs_pk);
        
        let mut hasher = SlugBlake2bHasher::new(48);
        let blake2b_hash_48 = SlugDigest::from_bytes(&hasher.hash(hashable_str.as_bytes())).expect("Failed To Get From Bytes").to_string().to_string();

        let mut hasher_id = SlugBlake2bHasher::new(8);
        let blake2b_id = SlugDigest::from_bytes(&hasher.hash(&blake2b_hash_48)).unwrap().to_string().to_string();

        
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
    pub fn get_delimter() -> String {
        return String::from(":")
    }
}