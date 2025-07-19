use chrono::prelude::*;

/// # Certificate Timestamping
/// 
/// The easy functionality for retrieving timestamps
pub struct CertTimestamping;

impl CertTimestamping {
    /// UTC Now
    pub fn now() {
        let utc: DateTime<Utc> = Utc::now();
    }
    /// Today
    pub fn today() {
        let utc: Date<Utc> = Utc::today();
    }
}