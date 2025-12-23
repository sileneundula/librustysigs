pub mod btc;

use bitcoin::Address as BtcAddress;
use bitcoin::AddressType as BtcAddressType;
use bitcoincash_addr::AddressCodec;
use bitcoincash_addr::cashaddr::CashAddrCodec;
use bitcoincash::Address as BchAddress;

use std::str::FromStr;

/// # Rustic Funds
/// 
/// A structure to hold multiple cryptocurrency addresses.
#[derive(Debug,Clone,PartialEq,PartialOrd)]
pub struct RusticFunds {
    primary_address: Address, // Bitcoin Cash
    // Additional addresses for other cryptocurrencies
    addresses: Vec<Address>, // addresses
    checksum: String, // 8-byte blake2b
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
    pub fn new<T: AsRef<str>>(_type: T, address: T) -> Result<Self, crate::errors::Errors> {

        let output = match _type.as_ref() {
            "BTC" => AddressType::BTC,
            "BCH" => AddressType::BCH,
            "ETH" => AddressType::ETH,
            _ => panic!("None given"),
        };

        if output == AddressType::BTC {
            if BtcAddress::from_str(address.as_ref()).is_ok() {
                return Ok(Address {
                    _type: _type.as_ref().to_string(),
                    address: address.as_ref().to_string(),
                })
            }
            else {
                return Err(crate::errors::Errors::InvalidBtcAddress);
            }
        }
        else if output == AddressType::ETH {
            // Ethereum Address Validation
            let eth_address = address.as_ref();
            if eth_address.len() == 42 && eth_address.starts_with("0x") {
                return Ok(Address {
                    _type: _type.as_ref().to_string(),
                    address: address.as_ref().to_string(),
                })
            } 
            else {
                return Err(crate::errors::Errors::InvalidEthAddress);
            }
        }
        else if output == AddressType::BCH {
            // Bitcoin Cash Address Validation
            if BchAddress:: {
                return Ok(Address {
                    _type: _type.as_ref().to_string(),
                    address: address.as_ref().to_string(),
                })
            } 
            else {
                return Err(crate::errors::Errors::InvalidBchAddress)
            }
        }
        else {
            return Err(crate::errors::Errors::UnknownAddressType)
        }

    }
}

/// # AddressType
/// 
/// - BTC (Bitcoin)
/// - BCH (Bitcoin Cash) (preferred)
/// - ETH (Ethereum)
#[derive(Debug,Clone,Copy,PartialEq,PartialOrd)]
pub enum AddressType {
    BTC,
    BCH,
    ETH,
}

#[test]
fn test() {
    let x = Address::new("BTC","bc1qp7z8g8rjhczpn28cpc0m5zyhycqh3af9sgcejn").unwrap();

    let _3 = Address::new("ETH", "0x5821ce4dCF1324a88A06b17e5d805201274e44f8").unwrap();

    let _2 = Address::new("BCH", "qp9lfwsfy6ffg855yq8hekcesc72fs6t3s79239lm9").unwrap();

}