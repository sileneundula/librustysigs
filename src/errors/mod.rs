#[derive(Debug)]
pub enum RustySignatureErrors {
    EncodingError(u8),
    
    
    ED25519Error(u8),
    SPHINCSError(u8)
}