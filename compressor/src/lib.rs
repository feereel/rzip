pub mod lzw;


#[derive(Debug, PartialEq)]
pub enum CompressorError {
    DecompressErrorWithCode,
    IncorrectSrcValue,
}

pub trait Compressor: Send + Sync {
    fn compress(&self, src: &[u8]) -> Vec<u8>;
    fn decompress(&self, src: &[u8]) -> Result<Vec<u8>, CompressorError>;
}