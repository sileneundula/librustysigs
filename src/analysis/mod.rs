//! # Analysis
//! 
//! ## TODO
//! 
//! - [ ] Analysis
//!     - [ ] Documentation
//!     - [ ] Audits
//!     - [ ] cargo.toml
//!     - [ ] code analysis
//!     - [ ] packages
//! 
//! - On server side, keep a table containing all check passes

pub struct Analyzer {
    language: AnalyzerLanguage,
}

pub struct RusticAnalysis;

impl RusticAnalysis {
    pub fn new() {
        
    }
}

pub enum AnalyzerLanguage {
    Rust,
    Typescript,
    Python,
    Go,
}