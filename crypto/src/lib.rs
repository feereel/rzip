mod mix;
mod utils;
mod constants;
pub mod threefish256;
pub mod cbc;


pub trait CipherBlock: Send + Sync {
    fn encrypt(&self, src: &[u8], dst: &mut [u8]) -> Result<(), CipherError>;
    fn decrypt(&self, src: &[u8], dst: &mut [u8]) -> Result<(), CipherError>;
    fn get_block_size(&self) -> usize;
}

#[derive(Debug, PartialEq)]
pub enum CipherError {
    InvalidKeyLength,
    InvalidTweakLength,
    InvalidPlaintextLength,
    InvalidCiphertextLength,
    InvalidIVLength,
    InvalidPaddingSize,
    InvalidIVArePassed,
}


pub trait CipherProcessor: Send + Sync {
    fn encrypt_blocks(&self, src: &[u8]) -> Vec<u8>;
    fn decrypt_blocks(&self, src: &[u8]) -> Result<Vec<u8>, CipherError>;
}

