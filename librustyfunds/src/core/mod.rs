pub mod btc;

use bitcoin::Address as BtcAddress;
use bitcoin::AddressType as BtcAddressType;
use bitcoincash_addr::Address as BchAddress;
use bitcoincash_addr::AddressCodec;
use bitcoincash_addr::cashaddr::CashAddrCodec;

use std::str::FromStr;

#[derive(Debug,Clone,PartialEq,PartialOrd)]
pub struct RusticFunds {
    primary_address: Address, // Bitcoin Cash
    addresses: Vec<(Address)>,
}

#[derive(Debug,Clone,PartialEq,PartialOrd)]
pub struct Address {
    _type: String,
    address: String,
}

impl Address {
    /// # New Address
    /// 
    /// Address Types:
    /// - BTC
    /// - BCH
    /// - ETH
    pub fn new<T: AsRef<str>>(_type: T, address: T) -> Self {

        let output = match _type.as_ref() {
            "BTC" => AddressType::BTC,
            "BCH" => AddressType::BCH,
            "ETH" => AddressType::ETH,
            _ => panic!("None given")
        };

        if output == AddressType::BTC {
            if BtcAddress::from_str(address.as_ref()).is_ok() {
                return Address {
                    _type: _type.as_ref().to_string(),
                    address: address.as_ref().to_string(),
                }
            } 
            else {
                panic!("Invalid BTC Address")
            }
        else if output == AddressType::BCH {
            // Handle BCH address validation here
        }
        }
        else {
            panic!("Unknown Address Type")
        }

    }
}

#[derive(Debug,Clone,Copy,PartialEq,PartialOrd)]
pub enum AddressType {
    BTC,
    BCH,
    ETH,
}