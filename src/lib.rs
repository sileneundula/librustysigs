//! # Rusty-Sigs (Library)
//! 
//! **Author:** [silene | 0x20CB | DionysianMyst | 0.25]
//! 
//! **Date Published:** July 2025
//! 
//! ## Description
//! 
//! This library is used for the interface for rusty-sigs verification of identities and other security-related functionality.
//! 
//! ## TODO
//! 
//! - [X] Basic Signature Implementation (ShulginSigning)
//!     - [X] ED25519
//!     - [X] SPHINCS+ (SHAKE256)
//!         - [X] Generation
//!         - [X] Signing
//!         - [X] Verification
//!         - [X] Add RNG
//!     - [X] RustySignatures
//!         - [X] SigningInfo (RNG + Digest)
//!     - [ ] Add Hash Derive
//! - [X] Hashing
//!     - [X] SHA3 (SHA3-224)
//!     - [X] BLAKE2s (8-byte)
//!     - [X] BLAKE2B (48-byte)
//! - [ ] Server To Store Keys
//!     - [ ] Decentralized
//!     - [ ] Nonce (PoW)
//! - [ ] GitHub Attribute Tag
//! - [ ] Security Audits
//! - [X] Zeroize
//! - [ ] Error-Checking
//! - [ ] Base58 ID
//! 
//! - [X] ShulginSigning
//!     - [X] Includes Cryptographic Randomness In Signature (using 64 bytes argon2id and oscsprng)
//!     - [X] Includes Public Key Checks Using SHA3-224
//! 
//! - [ ] Code Auditing
//!     - [ ] No Unsafe Code
//!     - [ ] Dependecies
//!     - [ ] Cargo.toml
//!     - [ ] Cargo.lock
//!     - [ ] .gitignore
//!     - [ ] LICENSE
//!     - [ ] README
//! 
//! - [ ] Work On Exporting The Certs in PKCS #7 or PEM
//! 
//! ## Code Example
//! 
//! ```rust
//! use librustysigs::prelude::*;
//! 
//! fn main() {
//!     // Certificates
//!     let full_certificate = UserCertificateFull::generate();
//!     let cert = full_certificate.publiccert();
//! 
//!     // Signature
//!     let signature = full_certificate.sign("This message is being signed by ED25519 and SPHINCS+ by librustysigs.", "silene");
//! 
//!     // Verify
//!     let is_valid_sig = RustySignaturesUsage::verify(cert, signature);
//! 
//!     // Asserts the signature is valid
//!     assert_eq!(is_valid_sig, true);
//! }
//! 
//! ```
//! 
//! ### Supported Algorithms
//! 
//! **Default:** `ShulginSigning` (ED25519/ED448 (with hedged signatures) + SPHINCS+ (SHAKE256))
//!     - Best used in scenarioes that need high security measures in authenticity.
//!     - Best used in scenarioes that need public keys to be short with ED25519 being 32-bytes and SPHINCS+ being 64-bytes
//!     - Slower Signing, but more secure against known attacks with high security assumptions based on hash functions.
//! 
//! **Alternative:** `AnneSigning` (ED25519/ED448 (with hedged signatures) + Dilihitum65)
//!     - Best used in scenarioes that need to have faster signatures and general security assumptions based on lattices.
//!     - Best used in scenarioes that need to have less size for signatures
//! 
//! **Alternative:** `WRCSigning` (ED25519/ED448 + FALCON1024)
//!     - Best used in scenarioes that need to have faster signatures and good security measures.
//!     - Best used in scenarioes that need to have less size for signatures
//! 
//! ### Definitions
//! 
//! The `RustySignatureUsage` is defined as:
//! 
//! - The interface in which you can interact easily with the project, basically, an abstraction.
//! 
//! The `PublicKeyID` is defined as the BLAKE2B(40) hash digest of the `SPHINCS+` and `ED25519` Public Keys in hexadecimal (upper-case) with a colon delimiter. The `ED25519 PK` preceeds the `SPHINCS+ PK` with a colon delimiter `:` and is then hashed as bytes.
//! 
//! The `EphermalSigningContext` is defined as an 8-12 byte BLAKE2b hash of the SigningInfo, including the Argon2id RNG + Operating System Randomness, public key random hash (SHA3-224), and the id (6 bytes).
//! 
//! The `UserCertificate` is defined as:
//! 
//! - A **Personal Certificate** tied to an individual, organization, or identity with respect to key awareness.
//! 
//! - A **Public Key Container** holding the classical public key (ED25519/ED448 with Hedged Signatures) and the post-quantum public key (SPHINCS+ (SHAKE256))
//! 
//! The `PrivUserCertificate` is defined as:
//! 
//! - A **Personal Certificate** tied to an individual, organization, or identity that proves ownership of `UserCertificate` and can be used to signing.
//! 
//! - A `UserCertificate` and **Secret Key Container** holding the classical secret keys (ED25519/ED448 with Hedged Signatures) and the post-quantum secret key (SPHINCS+ (SHAKE256)). Due to the UserCertificate being held, it also contains the public keys.
//! 
//! The `RustySignature` is defined as:
//! 
//! - the `Message`
//!     - bytes that represent the message, whether it be a vector of bytes or a hash.
//! - the `SigningInfo`
//!     - The SigningInfo includes the CSPRNG and Public Keys and is detailed below
//! - the `ED25519Signature`
//!     - 64 bytes
//!     - signature of (Message+SigningInfo), usually in the form of a hash
//! - the `SPHINCS+Signature`
//!     - 29792 bytes
//!     - signature of (Message+SigningInfo), usually in the form of a hash
//! 
//! The `SigningInfo` is defined as:
//!   - the `Argon2id`
//!     - Ephermal Password Based Fed Into ChaCha20RNG
//!   - the `OS-CSPRNG` (32-bytes)
//!     - Operating System Randomness
//! - the `pk_hash`
//!     - The SHA3-224 hash of ED25519:SPHINCS+ (hedged)
//! - the `id`
//!     - The 6-byte hash of the pk_hash (hedged)
//! 
//! ## Features
//! 
//! ### UserCertificate
//! 
//! The `UserCertificate` contains the following:
//! 
//! - [ ] Verification Methods
//! - [ ] Certificate Signing Request Feature
//!     - [ ] CSR-RS
//! - [ ] 
//! 
//! ### PrivUserCertificate
//! 
//! The `PrivUserCertificate` contains the following:
//! 
//! - [X] Signing
//! - [ ] Verifying Signatures 
//! 
//! ### RustySignature
//! 
//! - Integrity Checks on Data using:
//!     - BLAKE2B(64)
//!     - SHA2-384
//!     - BLAKE3
//! - Verification
//! 
//! ## License
//! 
//! APACHE-2.0

use libslug::slugcrypt::internals::messages::Message;
// Signatures
use libslug::slugcrypt::internals::signature::ed25519::{ED25519PublicKey,ED25519SecretKey,ED25519Signature}; // ED25519
use libslug::slugcrypt::internals::signature::sphincs_plus::{SPHINCSPublicKey,SPHINCSSignature,SPHINCSSecretKey}; // SPHINCS+ (SHAKE256) Level 5
use libslug::slugcrypt::internals::signature::ml_dsa::{SlugMLDSA3,MLDSA3Keypair,MLDSA3PublicKey,MLDSA3SecretKey,MLDSA3Signature}; // Dilihtium (ML-DSA65) Level 3

// Hash
use libslug::slugcrypt::internals::digest::sha3::Sha3Hasher; // SHA3-224
use libslug::slugcrypt::internals::digest::blake2::{SlugBlake2bHasher, SlugBlake2sHasher}; // BLAKE2s
use libslug::slugcrypt::internals::digest::digest::SlugDigest; // SlugDigest

use libslug::slugcrypt::internals::digest::sha2::Sha2Hasher;

// RNG
use libslug::slugcrypt::internals::csprng::SlugCSPRNG;

use zeroize::{Zeroize,ZeroizeOnDrop};

// Serialization
use serde::{Serialize,Deserialize};
use serde_yaml;

/// Registry for Keys
pub mod registry;

/// Timestamping Functionality
pub mod timestamping;

/// Analysis of Code/Repo
pub mod analysis;

/// Filesystem
pub mod fs;

/// All neccessary components
pub mod prelude;

pub mod rustyfunds;

pub mod x59;


/// # User Certificate
/// 
/// The User Certificate is used as a public certificate to verify signatures and store public keys.
/// 
/// ## Example Code
/// 
/// ```rust
/// use librustysigs::prelude::*;
/// 
/// fn main() {
///     let priv_cert = UserCertificatePriv::generate();
///     let cert = priv_cert.publiccert();
/// }
/// 
/// ```
#[derive(Serialize,Deserialize,Zeroize,ZeroizeOnDrop,Clone)]
pub struct UserCertificate {
    id: Option<u64>, // Stored on keyserver
    
    alg: Algorithms,

    clkey: ED25519PublicKey,
    pqkey: SPHINCSPublicKey,

}

/// # User Certificate (Private/Full)
/// 
/// The User Certificate is used to store the secret keys as well as a public certificate to generate keypairs and sign data.
/// 
/// ## Example Code
/// 
/// ```rust
/// use librustysigs::prelude::*;
/// 
/// fn main() {
///     let priv_cert = UserCertificatePriv::generate();
///     let cert = priv_cert.publiccert();
///     priv_cert.sign("This message is being signed by librustysigs using ED25519 and SPHINCS+", "password/nonce/rng")
/// }
/// 
/// ```
#[derive(Serialize,Deserialize,Zeroize,ZeroizeOnDrop,Clone)]
pub struct UserCertificatePriv {
    pub cert: UserCertificate,
    // Secrets
    pub clkeypriv: ED25519SecretKey,
    pub pqkeypriv: SPHINCSSecretKey,
    pub pqkeypub: SPHINCSPublicKey,
}

/// # RustySignature
/// 
/// Rusty Signature is the struct used for defining the signature and easily verifying it using:
/// 
/// - Message (a vector of bytes)
/// - SigningInfo (metadata and rng, as well as checks)
/// - Signatures (ED25519 and SPHINCS+)
#[derive(Serialize,Deserialize,Zeroize,ZeroizeOnDrop)]
pub struct RustySignature {
    message: Vec<u8>,
    signinginfo: SigningInfo,

    clsig: ED25519Signature,
    pqsig: SPHINCSSignature,
}

#[derive(Serialize,Deserialize,Zeroize,ZeroizeOnDrop)]
pub struct MessageHash(pub String);

#[derive(Serialize,Deserialize,Zeroize,ZeroizeOnDrop)]
pub struct MessageBytes(pub Vec<u8>);

#[derive(Serialize,Deserialize,Zeroize,ZeroizeOnDrop)]
pub struct PublicKeyDigest(pub String);

#[derive(Serialize,Deserialize,Zeroize,ZeroizeOnDrop)]
pub struct PublicKeyDigestID(pub String);


pub struct RustySignaturesUsage;

impl RustySignaturesUsage {
    /// # New Certificate
    /// 
    /// Generates a new certificate using ShulginSigning.
    pub fn new() -> UserCertificatePriv {
        UserCertificatePriv::generate()
    }
    /// # Verify
    /// 
    /// Verifies a signature against a user certificate.
    pub fn verify(cert: UserCertificate, sig: RustySignature) -> bool {
        let msg = Self::verification_process(&sig);
        let hash_validility = Self::verify_pk_rand(&cert, &sig);
        
        let classical = cert.clkey.verify(sig.clsig.clone(), &msg).expect("Failed To Verify ED25519 Signature or Message");
        let postquantum = cert.pqkey.verify(Message::new(&msg), sig.pqsig.clone()).expect("Failed To Verify SPHINCS+ Signature or Message");

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
        let digest = SlugDigest::from_bytes(&hasher.update(s.as_bytes())).expect("Failed To Hash");
        let final_digest = digest.to_string().to_string();

        let pk_hash = sig.signinginfo.pk_hash.clone();
        let id = sig.signinginfo.id.clone();

        let mut hasher = SlugBlake2sHasher::new(6);
        let output = hasher.update(&pk_hash);
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
        let digest = SlugDigest::from_bytes(&hasher.update(&x)).expect("Failed To Hash");
        let final_digest = digest.to_string().to_string();

        let pk_hash = sig.signinginfo.pk_hash.clone();
        let id = sig.signinginfo.id.clone();

        let mut hasher = SlugBlake2sHasher::new(6);
        let output = hasher.update(&pk_hash);
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

/// # SigningInfo
/// 
/// The `SigningInfo` is serialized to YAML and signed. It contains Argon2id RNG (with nonce), and OSCSPRNG for RNG. It also contains the public key hash with the RNG to thwart attacks on randomness while proving the public key in the signature. Finally, it contains the signature ID.
#[derive(Serialize,Deserialize,Zeroize,ZeroizeOnDrop, Clone)]
pub struct SigningInfo {
    pub argon: [u8;32],
    pub oscsprng: [u8;32],
    pub pk_hash: String, // SHA3-224 (ED25519:SPHINCS+)
    pub id: String, // 6-byte of pk_hash
}

impl SigningInfo {
    /// Serialize to YAML
    pub fn yamalize(&self) -> String {
        let signing_info = serde_yaml::to_string(&self).expect("Failed To Serialize SigningInfo");
        return signing_info
    }
}

impl RustySignature {
    fn integrity_blake2(&self) -> Vec<u8> {
        // 512 Blake2B | Switch to Blake2s on no_std version
        let hasher = SlugBlake2bHasher::new(64);
        return hasher.update(&self.message);
    }
    fn integrity_sha384(&self) -> Vec<u8> {
        let hasher = Sha2Hasher::new(384);
        hasher.update(&self.message)
    }
    pub fn get_integrity_as_bytes(&self, hasher: RustySignatureHashingIntegrity) -> Vec<u8> {
        let output = match hasher {
            RustySignatureHashingIntegrity::BLAKE2b_64 => self.integrity_blake2(),
            RustySignatureHashingIntegrity::SHA2_384 => self.integrity_sha384(),
        };

        return output
    }
    pub fn integrity(&self, hasher: RustySignatureHashingIntegrity) -> String {
        let output = SlugDigest::from_bytes(&self.get_integrity_as_bytes(hasher)).unwrap().to_string().to_string();
        return output
    }
}

enum RustySignatureHashingIntegrity {
    BLAKE2b_64,
    SHA2_384,
}

pub struct Signer;

impl Signer {
    /// # Add To Signing
    /// 
    /// This method adds certain information to the signing process.
    pub fn add_to_signing<T: AsRef<str>>(nonce_pass: T, pk: &ED25519PublicKey, pksphincs: &SPHINCSPublicKey) -> SigningInfo {
        // - PublicKey Hash
        // - Add CSPRNG
        let (argonrng, oscsprng) = Self::csprng(nonce_pass.as_ref());
        // PK_HASH
        //let pk_hash = Self::key(pk,pksphincs);
        // PK_HASH RANDOMIZED (Signed)
        let pk_hash_randomnized_for_signing = Self::key_rand(&argonrng, &oscsprng, pk, pksphincs);
        //let id = Self::id(&pk_hash);
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

        let output = hasher.update(input_pk.as_bytes());
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

        let output = hasher.update(&input_to_hash);
        let final_hash = SlugDigest::from_bytes(&output).unwrap();
        return final_hash.to_string().to_string()
    }
    fn id(s: &str) -> String {
        let mut hasher = SlugBlake2sHasher::new(6);
        let x = SlugDigest::from_bytes(&hasher.update(s.as_bytes())).expect("Failed To Use BLAKE2s");
        x.to_string().to_string()
    }
}

// TODO: Fix CLONING

impl UserCertificatePriv {
    /// # Generate
    /// 
    /// Generates a new certificate
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
    /// # Sign
    /// 
    /// Signs new data with a nonce/password for added entropy. The message is anything that can be convert to bytes. It then returns the RustySignature.
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
    /// Return `UserCertificate`
    pub fn publiccert(&self) -> UserCertificate {
        return self.cert.clone()
    }
}


/// # Algorithms
/// 
/// The Algorithms list the algorithms used in librustysigs. By default, ShulginSigning (ED25519+SPHINCS+ (SHAKE256)) is used.
/// 
/// The Algorithms are listed below:
/// 
/// 1. ShulginSigning
/// 2. AnneSigning
/// 3. ED25519
#[derive(Serialize,Deserialize,Clone,PartialEq,PartialOrd,Zeroize,ZeroizeOnDrop)]
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
    let privcert = UserCertificatePriv::generate();
    let rustysig = privcert.sign("This is my first message on the internet","123456789");

    let cert = privcert.publiccert();

    let sig_validility = RustySignaturesUsage::verify(cert, rustysig);

    println!("Is Valid: {}", sig_validility)
}