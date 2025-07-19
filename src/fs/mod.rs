//! # File System
//! 
//! The File System is looking for a rusty.cert file in the repo

use libslug::slugcrypt::internals::signature::{ed25519::ED25519PublicKey, sphincs_plus::SPHINCSPublicKey};

use crate::registry::ShulginSigning;


/// # RustyFileKeys
/// 
/// This contains all needed information.
pub struct RustyFileKeys {
    authors: Vec<String>,
    organization: String,
    
    domain: String,
    email: String,

    keys: ShulginSigning,
}

/// # RustyFileMeta
/// 
/// Metadata
pub struct RustyFileMeta {
    languages: Vec<Languages>,
    softwarelangauge: SoftwareLanguage,
}

/// # RustyFileConfig
/// 
/// This is the config file.
pub struct RustyFileConfig {
    softwarelanguage: SoftwareLanguage,
}

/// # SoftwareLanguage
/// 
/// This lists the software used.
pub enum SoftwareLanguage {
    Rust,
}

/// # Languages
/// 
/// This list the languages the data is in.
pub enum Languages {
    en,
    ch,
    ru,
}