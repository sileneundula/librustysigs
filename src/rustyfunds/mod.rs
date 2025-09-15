//! # RustyFunds
//! 
//! Meant to serve as a decentralized source of funds using different currency. It is strictly decentralized to enhance creation and other means.
//! 
//! Default Currency: BCH (due to lower tx fees)
//! Alternatives: BTC, ETH, XLM, Nano, XMR
//! 
//! [] Add smart contract integration
//!     [] ETH Verifiy
//! [] Add generate addresses (wallet)

use serde::{Serialize,Deserialize};

pub struct RustyFunds;

pub struct RustyFundsBCH {
    address: String,
}

impl RustyFundsBCH {
    pub fn new<T: AsRef<str>>(address: T) -> Self {
        Self {
            address: address.as_ref().to_string(),
        }
    }
}

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
    pub fn new(btc: String, bch: String) -> RustyFundsSources {
        return RustyFundsSources {
            btc: FundingSources::BTC(btc),
            bch: Some(FundingSources::BCH(bch)),
            eth: None,
            xlm: None,
            nano: None,
            xmr: None,
        }
    }
}