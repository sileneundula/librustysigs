//! # RustyFunds
//! 
//! [] Add smart contract integration
//!     [] ETH Verifiy
//! [] Add generate addresses (wallet)

use serde::{Serialize,Deserialize};

pub struct RustyFunds;

#[derive(Serialize,Deserialize, Clone)]
pub enum FundingSources {
    BTC(String),
    BCH(String),
    ETH(String),

    // Others
    XLM(String), // stellar
    Nano(String),

    // Security
    XMR(String),
}

#[derive(Serialize,Deserialize, Clone)]
pub struct RustyFundsSources {
    btc: FundingSources,
    bch: Option<FundingSources>,
    eth: Option<FundingSources>,
    xlm: Option<FundingSources>,
    nano: Option<FundingSources>,
    xmr: Option<FundingSources>,
}

impl RustyFunds {
    pub fn new(btc: String) -> RustyFundsSources {
        return RustyFundsSources {
            btc: FundingSources::BTC(btc),
            bch: None,
            eth: None,
            xlm: None,
            nano: None,
            xmr: None,
        }
    }
}