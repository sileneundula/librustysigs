use chrono::prelude::*;

/// # Certificate Timestamping
/// 
/// The easy functionality for retrieving timestamps.
/// 
/// **Certificate-Request:** It should only go by day.
pub struct CertTimestamping;

impl CertTimestamping {
    /// UTC Now
    pub fn now() {
        let utc: DateTime<Utc> = Utc::now();
    }
    /// # Today
    /// 
    /// Use the following code
    /// 
    /// ```rust
    /// use librustysigs::prelude::*;
    /// 
    /// fn main() {
    ///     let day = CertTimestamping::today();
    /// }
    /// ```
    pub fn today() {
        let utc: Date<Utc> = Utc::today();
    }
}