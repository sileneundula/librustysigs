//! # Rusty-Sigs (Library)
//! 
//! This library is used for the interface for rusty-sigs verification of identities and other security-related functionality.
//! 
//! ## TODO
//! 
//! - [] Basic Signature Implementation
//!     - [X] ED25519
//!     - [X] SPHINCS+ (SHAKE256)
//!         - [X] Generation
//!         - [X] Signing
//!         - [X] Verification
//!         - Add RNG
//! - [X] Hashing
//!     - [X] SHA3 (SHA3-224)
//!     - [X] BLAKE2s (8-byte)
//! - [] Server To Store Keys
//!     - [] Decentralized
//!     - [] Nonce (PoW)
//! - [] GitHub Attribute Tag
//! - [] Security Audits
//! - [] Zeroize
//! - [] Error-Checking
//! - [] Base58 ID
//! 
//! - [X] ShulginSigning
//!     - [X] Includes Cryptographic Randomness In Signature (using 64 bytes argon2id and oscsprng)
//!     - [X] Includes Public Key Checks Using SHA3-224
//! 
//! - [] Code Auditing
//!     - [] No Unsafe Code
//!     - [] Dependecies
//!     - [] Cargo.toml
//!     - [] Cargo.lock
//!     - [] .gitignore
//!     - [] LICENSE
//!     - [] README
//! 
//! 
//! Key Each Hash Iteration With Randomness
//! 
//! 

use libslug::slugcrypt::internals::messages::Message;
// Signatures
use libslug::slugcrypt::internals::signature::ed25519::{ED25519PublicKey,ED25519SecretKey,ED25519Signature}; // ED25519
use libslug::slugcrypt::internals::signature::sphincs_plus::{SPHINCSPublicKey,SPHINCSSignature,SPHINCSSecretKey}; // SPHINCS+ (SHAKE256) Level 5
use libslug::slugcrypt::internals::signature::ml_dsa::{SlugMLDSA3,MLDSA3Keypair,MLDSA3PublicKey,MLDSA3SecretKey,MLDSA3Signature}; // Dilihtium (ML-DSA65) Level 3

// Hash
use libslug::slugcrypt::internals::digest::sha3::Sha3Hasher; // SHA3-224
use libslug::slugcrypt::internals::digest::blake2::SlugBlake2sHasher; // BLAKE2s
use libslug::slugcrypt::internals::digest::digest::SlugDigest; // SlugDigest

// RNG
use libslug::slugcrypt::internals::csprng::SlugCSPRNG;

// Serialization
use serde::{Serialize,Deserialize};
use serde_yaml;

/// Registry for Keys
pub mod registry;

pub mod timestamping;

pub mod analysis;

pub mod fs;


#[derive(Serialize,Deserialize,Clone)]
pub struct UserCertificate {
    id: Option<u64>, // Stored on keyserver
    
    alg: Algorithms,

    clkey: ED25519PublicKey,
    pqkey: SPHINCSPublicKey,

}

#[derive(Serialize,Deserialize,Clone)]
pub struct UserCertificateFull {
    cert: UserCertificate,
    // Secrets
    clkeypriv: ED25519SecretKey,
    pqkeypriv: SPHINCSSecretKey,
    pqkeypub: SPHINCSPublicKey,
}

#[derive(Serialize,Deserialize)]
pub struct RustySignature {
    message: Vec<u8>,
    signinginfo: SigningInfo,

    clsig: ED25519Signature,
    pqsig: SPHINCSSignature,
}

#[derive(Serialize,Deserialize)]
pub struct MessageHash(pub String);

#[derive(Serialize,Deserialize)]
pub struct MessageBytes(pub Vec<u8>);

#[derive(Serialize,Deserialize)]
pub struct PublicKeyDigest(pub String);

#[derive(Serialize,Deserialize)]
pub struct PublicKeyDigestID(pub String);


pub struct RustySignaturesUsage;

impl RustySignaturesUsage {
    pub fn new() -> UserCertificateFull {
        UserCertificateFull::generate()
    }
    pub fn verify(cert: UserCertificate, sig: RustySignature) -> bool {
        let msg = Self::verification_process(&sig);
        let hash_validility = Self::verify_pk_rand(&cert, &sig);
        
        let classical = cert.clkey.verify(sig.clsig, &msg).expect("Failed To Verify ED25519 Signature or Message");
        let postquantum = cert.pqkey.verify(Message::new(&msg), sig.pqsig).expect("Failed To Verify SPHINCS+ Signature or Message");

        if classical == true && postquantum == true && hash_validility == true {
            return true
        }
        else {
            return false
        }
    }
    fn verification_process(sig: &RustySignature) -> Vec<u8> {
        let mut v = Vec::new();
        v.extend_from_slice(sig.signinginfo.yamalize().as_bytes());
        v.extend_from_slice(&sig.message);

        return v
    }
    fn verify_pk(cert: &UserCertificate, sig: &RustySignature) -> bool {

        let mut s: String = String::new();

        s.push_str(cert.clkey.to_hex_string().as_str());
        s.push_str(":");
        s.push_str(cert.pqkey.to_hex_string().expect("Failed To Get SPHINCS+").as_str());

        let mut hasher = Sha3Hasher::new(224);
        let digest = SlugDigest::from_bytes(&hasher.digest(s.as_bytes())).expect("Failed To Hash");
        let final_digest = digest.to_string().to_string();

        let pk_hash = sig.signinginfo.pk_hash.clone();
        let id = sig.signinginfo.id.clone();

        let mut hasher = SlugBlake2sHasher::new(6);
        let output = hasher.hash(&pk_hash);
        let blake2s_digest = SlugDigest::from_bytes(&output).unwrap();
        let final_blake2s_digest = blake2s_digest.to_string().to_string();

        if pk_hash.clone() == final_digest && id.clone() == final_blake2s_digest {
            return true
        }
        else {
            return false
        }
    }
    fn verify_pk_rand(cert: &UserCertificate, sig: &RustySignature) -> bool {
        let mut x: Vec<u8> = vec![];
        let mut s: String = String::new();

        s.push_str(cert.clkey.to_hex_string().as_str());
        s.push_str(":");
        s.push_str(cert.pqkey.to_hex_string().expect("Failed To Get SPHINCS+").as_str());

        x.extend_from_slice(&sig.signinginfo.argon);
        x.extend_from_slice(&sig.signinginfo.oscsprng);
        x.extend_from_slice(s.as_bytes());

        let mut hasher = Sha3Hasher::new(224);
        let digest = SlugDigest::from_bytes(&hasher.digest(&x)).expect("Failed To Hash");
        let final_digest = digest.to_string().to_string();

        let pk_hash = sig.signinginfo.pk_hash.clone();
        let id = sig.signinginfo.id.clone();

        let mut hasher = SlugBlake2sHasher::new(6);
        let output = hasher.hash(&pk_hash);
        let blake2s_digest = SlugDigest::from_bytes(&output).unwrap();
        let final_blake2s_digest = blake2s_digest.to_string().to_string();

        if pk_hash.clone() == final_digest && id.clone() == final_blake2s_digest {
            return true
        }
        else {
            return false
        }
    }
}

#[derive(Serialize,Deserialize, Clone)]
pub struct SigningInfo {
    pub argon: [u8;32],
    pub oscsprng: [u8;32],
    pub pk_hash: String, // SHA3-224 (ED25519:SPHINCS+)
    pub id: String, // 6-byte of pk_hash
}

impl SigningInfo {
    pub fn yamalize(&self) -> String {
        let signing_info = serde_yaml::to_string(&self).expect("Failed To Serialize SigningInfo");
        return signing_info
    }
}

pub struct Signer;

impl Signer {
    pub fn add_to_signing<T: AsRef<str>>(nonce_pass: T, pk: &ED25519PublicKey, pksphincs: &SPHINCSPublicKey) -> SigningInfo {
        // - PublicKey Hash
        // - Add CSPRNG
        let (argonrng, oscsprng) = Self::csprng(nonce_pass.as_ref());
        // PK_HASH
        let pk_hash = Self::key(pk,pksphincs);
        // PK_HASH RANDOMIZED (Signed)
        let pk_hash_randomnized_for_signing = Self::key_rand(&argonrng, &oscsprng, pk, pksphincs);
        let id = Self::id(&pk_hash);
        let id_rand = Self::id(&pk_hash_randomnized_for_signing);

        return SigningInfo {
            argon: argonrng,
            oscsprng: oscsprng,
            // RNG-Signed
            pk_hash: pk_hash_randomnized_for_signing, // SHA3-224
            id: id_rand
        }
        

    }
    fn csprng<T: AsRef<str>>(nonce_pass: T) -> ([u8;32],[u8;32]) {
        let csprng = SlugCSPRNG::new(nonce_pass.as_ref());
        let os_csprng = SlugCSPRNG::os_rand();

        (csprng,os_csprng)
    }
    fn key(pk: &ED25519PublicKey, pksphincs: &SPHINCSPublicKey) -> String {
        let mut hasher = Sha3Hasher::new(224);
        let mut input_pk: String = String::new();

        input_pk.push_str(&pk.to_hex_string());
        input_pk.push_str(":");
        input_pk.push_str(&pksphincs.to_hex_string().expect("Failed To Get SPHINCS+"));

        let output = hasher.digest(input_pk.as_bytes());
        let final_hash = SlugDigest::from_bytes(&output).expect("Failed To Get Hash From Bytes");
        return final_hash.to_string().to_string()
    }
    fn key_rand(argon: &[u8], csprng: &[u8], pk: &ED25519PublicKey, pksphincs: &SPHINCSPublicKey) -> String {
        let mut hasher = Sha3Hasher::new(224);
        let mut input_to_hash: Vec<u8> = vec![];
        
        let mut input_pk: String = String::new();

        input_pk.push_str(&pk.to_hex_string());
        input_pk.push_str(&":");
        input_pk.push_str(&pksphincs.to_hex_string().expect("Failed To Convert To Hex String"));

        input_to_hash.extend_from_slice(argon);
        input_to_hash.extend_from_slice(csprng);
        input_to_hash.extend_from_slice(input_pk.as_bytes());

        let output = hasher.digest(&input_to_hash);
        let final_hash = SlugDigest::from_bytes(&output).unwrap();
        return final_hash.to_string().to_string()
    }
    fn id(s: &str) -> String {
        let mut hasher = SlugBlake2sHasher::new(6);
        let x = SlugDigest::from_bytes(&hasher.hash(s.as_bytes())).expect("Failed To Use BLAKE2s");
        x.to_string().to_string()
    }
}

// TODO: Fix CLONING

impl UserCertificateFull {
    pub fn generate() -> Self {
        // Generate Secret Key
        let ed25519sk = ED25519SecretKey::generate();

        // Generate SPHINCS+ Keypair
        let (sphincspk,sphincssk) = SPHINCSSecretKey::generate();

        return Self {
            cert: UserCertificate { 
                id: None, 
                alg: Algorithms::ShulginSigning, 
                clkey: ed25519sk.public_key().expect("Failed To Convert ED25519 To Public Key"), 
                pqkey: sphincspk.clone() 
            },
            clkeypriv: ed25519sk,
            pqkeypriv: sphincssk,
            pqkeypub: sphincspk.clone(),
        }
    }
    pub fn sign<T: AsRef<[u8]>, U: AsRef<str>>(&self, message: T, password: U) -> RustySignature {
        let signing_info = Signer::add_to_signing(password.as_ref(), &self.cert.clkey, &self.cert.pqkey);
        
        // =====The Value Being Signed======
        let mut to_be_signed: Vec<u8> = Vec::new();
        
        let serialized_signing_info = signing_info.yamalize();
        to_be_signed.extend_from_slice(serialized_signing_info.as_bytes());
        to_be_signed.extend_from_slice(message.as_ref());
        
        let sig = self.clkeypriv.sign(&to_be_signed).unwrap();
        let sphincssig = self.pqkeypriv.sign(Message::new(&to_be_signed)).unwrap();

        return RustySignature {
            message: message.as_ref().to_vec(),
            signinginfo: signing_info,


            clsig: sig,
            pqsig: sphincssig,
        }
    }
    pub fn export(&self) {

    }
    pub fn publiccert(&self) -> UserCertificate {
        return self.cert.clone()
    }
}


#[derive(Serialize,Deserialize,Clone,Copy,PartialEq,PartialOrd)]
pub enum Algorithms {
    ShulginSigning, // ED448 (or ED25519) + SPHINCS+ (SHAKE256) (ML-SLH)
    // SPHINCS+ (Post-Quantum)
    // PK: 32-64 bytes
    // SK: 64-128 bytes
    // Signature: 29_000
    // Speed: SLOW BUT SECURE
    // Hash Functions
    AnneSigning,
    // Dilithium (ML-DSA65) (Post-Quantum) + ED448/ED25519
    // PK: 1000-2000 bytes
    // SK: ~2000 bytes
    // Sig: ~4000 bytes
    // Speed: FAST
    // Lattices
    ED25519,
}


#[test]
fn nw() {
    let privcert = UserCertificateFull::generate();
    let rustysig = privcert.sign("This is my first message on the internet","123456789");

    let cert = privcert.publiccert();

    let sig_validility = RustySignaturesUsage::verify(cert, rustysig);

    println!("Is Valid: {}", sig_validility)
}