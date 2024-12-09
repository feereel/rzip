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
        if src.len() == 0{
            return Vec::new();
        }

        let mut dict = self.init_dict.clone();
        
        let mut tmp: Vec<u8> = Vec::new();
        let mut key = Vec::new();

        let mut writes = 0;

        for &symbol in src {
            let mut word = key.clone();
            word.push(symbol);

            if !dict.contains_key(&word) {
                if let Some(&code) = dict.get(&key) {
                    let bytes: [u8; 4] = code.to_ne_bytes();
                    tmp.extend_from_slice(&bytes);
                    writes+=1;
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
                tmp.extend_from_slice(&bytes);
                writes+=1;
            }
        }

        let mut pow = dict.len().ilog2();
        if !dict.len().is_power_of_two() {
            pow += 1;
        }

        let size = (pow + 7) / 8;
        let result_len = (writes * size + 1) as usize;
        if result_len > src.len() {
            return src.to_vec();
        }

        let mut result = Vec::with_capacity(result_len);
        result.push(size as u8);
        for i in 0..writes as usize{
            for j in 0..size as usize {
                let x = tmp[i*4 + j];
                result.push(x);
            }
        }

        result
    }

    fn decompress(&self, src: &[u8]) -> Result<Vec<u8>, CompressorError> {
        if src.len() == 0{
            return Ok(Vec::new());
        }

        let size: usize = src[0] as usize;
        if (src.len() - 1) % size != 0{
            return Err(CompressorError::IncorrectSrcValue);
        }

        let mut dict: Vec<Vec<u8>> = Vec::with_capacity(256);
    
        for word in 0..256 {
            dict.push(vec![word as u8]);
        }

        let mut src = src[1..]
            .chunks(size)
            .map(|chunk| {
                let mut array = [0u8; 4];
                array[..chunk.len()].copy_from_slice(chunk);
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

        let expected = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 3, 4, 5, 6, 7, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 4, 5, 2, 3, 3, 4, 3, 4, 5, 6, 6, 7, 8, 9, 3, 5, 6, 7, 8, 9, 2, 4, 5, 5, 5, 5, 5, 5, 5, 1];

        assert_eq!(compressed, expected);
    }

    #[test]
    fn decompress_errors() {
        let lzw = LZW::new();

        let compressed: Vec<u8> = vec![4,0,0,0,0,1,0,0,0,2,0,0,];
        let r = lzw.decompress(&compressed);
        assert!(r.is_err());
        assert_eq!(r.unwrap_err(), CompressorError::IncorrectSrcValue);

        let compressed: Vec<u8> = vec![2,0,0,2];
        let r = lzw.decompress(&compressed);
        assert!(r.is_err());
        assert_eq!(r.unwrap_err(), CompressorError::IncorrectSrcValue);

        let compressed: Vec<u8> = vec![3,1,0,0];
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
            2, 0, 0, 1, 0, 2, 0, 3, 0, 4, 0, 5, 0, 6, 0, 7, 0, 8,
            0, 9, 0, 0, 1, 2, 1, 4, 0, 3, 1, 5, 1, 7, 0, 10, 1, 13,
            1, 6, 1, 8, 1, 4, 1, 2, 1, 3, 1, 17, 1, 18, 1, 9, 0, 3,
            0, 14, 1, 8, 1, 2, 0, 4, 1, 5, 0, 31, 1, 32, 1, 1, 0
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
