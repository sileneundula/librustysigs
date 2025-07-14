//! # File System
//! 
//! The File System is looking for a rusty.cert file in the repo

use libslug::slugcrypt::internals::signature::{ed25519::ED25519PublicKey, sphincs_plus::SPHINCSPublicKey};

use crate::registry::ShulginSigning;

pub struct RustyFileKeys {
    authors: Vec<String>,
    organization: String,
    
    domain: String,
    email: String,

    keys: ShulginSigning,
}

pub struct RustyFileMeta {
    languages: Vec<Languages>,
    softwarelangauge: SoftwareLanguage,
}

pub struct RustyFileConfig {
    softwarelanguage: SoftwareLanguage,
}

pub enum SoftwareLanguage {
    Rust,
}

pub enum Languages {
    en,
    ch,
    ru,
}