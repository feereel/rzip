use super::CompressorError;
use super::Compressor;

use std::collections::HashMap;


#[derive(Debug)]
pub struct LZW {
    init_dict: HashMap<Vec<u8>, u32>,
}

impl LZW {
    fn get_default_dict() -> HashMap<Vec<u8>, u32>{
        let mut dict: HashMap<Vec<u8>, u32> = HashMap::new();
    
        for i in 0..256 {
            dict.insert(vec![i as u8], i);
        }
    
        dict
    }

    pub fn new() -> LZW {
        LZW{
            init_dict: LZW::get_default_dict(),
        }
    }

    pub fn compress(&self, src: &[u8]) -> Vec<u8> {
        Compressor::compress(self, src)
    }

    pub fn decompress(&self, src: &[u8]) -> Result<Vec<u8>, CompressorError> {
        Compressor::decompress(self, src)
    }
}

impl Compressor for LZW {
    fn compress(&self, src: &[u8]) -> Vec<u8> {
        let mut dict = self.init_dict.clone();
        
        let mut result: Vec<u8> = Vec::new();
        let mut key = Vec::new();

        for &symbol in src {
            let mut word = key.clone();
            word.push(symbol);

            if !dict.contains_key(&word) {
                if let Some(&code) = dict.get(&key) {
                    let bytes: [u8; 4] = code.to_ne_bytes();
                    result.extend_from_slice(&bytes);
                }
                dict.insert(word.clone(), dict.len() as u32);

                key.clear();
                key.push(symbol);
            } else {
                key = word;
            }
        }

        if !key.is_empty() {
            if let Some(&code) = dict.get(&key) {
                let bytes: [u8; 4] = code.to_ne_bytes();
                result.extend_from_slice(&bytes);
            }
        }
        result
    }

    fn decompress(&self, src: &[u8]) -> Result<Vec<u8>, CompressorError> {
        if src.len() == 0{
            return Ok(Vec::new());
        }

        if src.len() % 4 != 0{
            return Err(CompressorError::IncorrectSrcValue);
        }

        let mut dict: Vec<Vec<u8>> = Vec::with_capacity(256);
    
        for word in 0..256 {
            dict.push(vec![word as u8]);
        }

        let mut src = src
            .chunks(4)
            .map(|chunk| {
                let mut array = [0u8; 4];
                array.copy_from_slice(chunk);
                u32::from_ne_bytes(array)
            });
    
        let first_code = src.next().unwrap();
        let mut var = dict[first_code as usize].clone();
        let mut result: Vec<u8> = var.clone();
    
        for code in src {
            let mut entry: Vec<u8>;
    
            if code < dict.len() as u32 {
                entry = dict[code as usize].clone();
            } else if code == dict.len() as u32 {
                entry = var.clone();
                entry.push(var[0]);
            } else {
                return Err(CompressorError::DecompressErrorWithCode);
            }
    
            result.extend(&entry);
    
            let mut new_entry: Vec<u8> = var.clone();
            new_entry.push(entry[0]);
            dict.push(new_entry);
            
            var = entry;
        }
    
        Ok(result)
    }
}


#[cfg(test)]
mod lzw_test {
    use super::*;

    #[test]
    fn compress_res() {
        let lzw = LZW::new();

        let uncompressed = vec![
            0u8,1,2,3,4,5,6,7,8,9,
            0,1,2,3,4,3,4,5,6,7,
            0,1,2,3,4,5,6,7,8,9,
            4,5,2,3,3,4,3,4,5,6,
            6,7,8,9,3,5,6,7,8,9,
            2,4,5,5,5,5,5,5,5,1,
        ];

        let compressed = lzw.compress(&uncompressed);

        let expected = vec![
            0u8, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0,
            4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0,
            8, 0, 0, 0, 9, 0, 0, 0, 0, 1, 0, 0, 2, 1, 0, 0,
            4, 0, 0, 0, 3, 1, 0, 0, 5, 1, 0, 0, 7, 0, 0, 0,
            10, 1, 0, 0, 13, 1, 0, 0, 6, 1, 0, 0, 8, 1, 0, 0,
            4, 1, 0, 0, 2, 1, 0, 0, 3, 1, 0, 0, 17, 1, 0, 0,
            18, 1, 0, 0, 9, 0, 0, 0, 3, 0, 0, 0, 14, 1, 0, 0,
            8, 1, 0, 0, 2, 0, 0, 0, 4, 1, 0, 0, 5, 0, 0, 0,
            31, 1, 0, 0, 32, 1, 0, 0, 1, 0, 0, 0
        ];

        assert_eq!(compressed, expected);
    }

    #[test]
    fn decompress_errors() {
        let lzw = LZW::new();

        let compressed: Vec<u8> = vec![0,0,0,0,1,0,0,0,2,0,0,];
        let r = lzw.decompress(&compressed);
        assert!(r.is_err());
        assert_eq!(r.unwrap_err(), CompressorError::IncorrectSrcValue);

        let compressed: Vec<u8> = vec![0,0,0];
        let r = lzw.decompress(&compressed);
        assert!(r.is_err());
        assert_eq!(r.unwrap_err(), CompressorError::IncorrectSrcValue);

        let compressed: Vec<u8> = vec![1,0,0,0];
        let r = lzw.decompress(&compressed);

        assert!(!r.is_err());

        let compressed: Vec<u8> = Vec::new();
        let r = lzw.decompress(&compressed);

        assert!(!r.is_err());
        assert_eq!(r.unwrap(), Vec::new());
        
    }

    #[test]
    fn decompress_res() {
        let lzw = LZW::new();

        let compressed = vec![
            0u8, 0, 0, 0, 1, 0, 0, 0, 2, 0, 0, 0, 3, 0, 0, 0,
            4, 0, 0, 0, 5, 0, 0, 0, 6, 0, 0, 0, 7, 0, 0, 0,
            8, 0, 0, 0, 9, 0, 0, 0, 0, 1, 0, 0, 2, 1, 0, 0,
            4, 0, 0, 0, 3, 1, 0, 0, 5, 1, 0, 0, 7, 0, 0, 0,
            10, 1, 0, 0, 13, 1, 0, 0, 6, 1, 0, 0, 8, 1, 0, 0,
            4, 1, 0, 0, 2, 1, 0, 0, 3, 1, 0, 0, 17, 1, 0, 0,
            18, 1, 0, 0, 9, 0, 0, 0, 3, 0, 0, 0, 14, 1, 0, 0,
            8, 1, 0, 0, 2, 0, 0, 0, 4, 1, 0, 0, 5, 0, 0, 0,
            31, 1, 0, 0, 32, 1, 0, 0, 1, 0, 0, 0
        ];

        let uncompressed = lzw.decompress(&compressed).unwrap();

        let expected = vec![
            0u8,1,2,3,4,5,6,7,8,9,
            0,1,2,3,4,3,4,5,6,7,
            0,1,2,3,4,5,6,7,8,9,
            4,5,2,3,3,4,3,4,5,6,
            6,7,8,9,3,5,6,7,8,9,
            2,4,5,5,5,5,5,5,5,1,
        ];

        assert_eq!(uncompressed, expected);
    }
}
