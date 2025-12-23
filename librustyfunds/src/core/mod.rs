//! # Rustic Funds
//! 
//! 


pub mod btc;

use bitcoin::Address as BtcAddress;
use bitcoin::AddressType as BtcAddressType;

use blake2_rfc::blake2b::Blake2b;

use bs58;

use std::str::FromStr;

/// # Rustic Funds
/// 
/// A structure to hold multiple cryptocurrency addresses.
#[derive(Debug,Clone,PartialEq,PartialOrd)]
pub struct RusticFunds {
    pub primary_address: Address, // Bitcoin Cash
    // Additional addresses for other cryptocurrencies
    pub addresses: Option<Vec<Address>>, // addresses
    pub checksum: Option<String>, // 8-byte blake2b
}

impl RusticFunds {
    pub fn new(addr: Address) -> Self {

        let mut address = Self {
            primary_address: addr,
            addresses: None,
            checksum: None,
        };

        let checksum = address.checksum_8();

        address.checksum = Some(checksum);

        return address
    }
    /// Checksum In BLAKE2B(8) Encoded in Base58
    fn checksum_8(&self) -> String {
        let mut hasher = Blake2b::new(8);

        let addresses = Self::get_addresses(&self);

        for x in addresses {
            hasher.update(&x._type.as_bytes());
            hasher.update(&x.address.as_bytes());
        }

        let output = hasher.finalize().as_bytes();
        
        let state = bs58::encode(output).into_string();

        return state
        
    }
    fn get_addresses(&self) -> Vec<Address> {
        let mut sorted: Vec<Address> = vec![];

        sorted.push(self.primary_address.clone());
        
        if self.addresses.is_some() {

            let added_addresses: Vec<Address> = self.addresses.clone().unwrap();
            
            for i in added_addresses {
                sorted.push(i);
            }
        }
        else {
            return sorted
        }
        return sorted
    }
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
            if  {
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