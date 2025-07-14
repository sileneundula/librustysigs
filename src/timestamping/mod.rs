use chrono::prelude::*;

pub struct CertTimestamping;

impl CertTimestamping {
    pub fn now() {
        let utc: DateTime<Utc> = Utc::now();
    }
    pub fn today() {
        let utc: Date<Utc> = Utc::today();
    }
}