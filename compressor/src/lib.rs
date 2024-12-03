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

    pub fn compress(&self, src: &[u8]) -> Vec<u32> {
        let mut dict = self.init_dict.clone();
        
        let mut result: Vec<u32> = Vec::new();
        let mut key = Vec::new();

        for &symbol in src {
            let mut word = key.clone();
            word.push(symbol);

            if !dict.contains_key(&word) {
                if let Some(&code) = dict.get(&key) {
                    result.push(code);
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
                result.push(code);
            }
        }
        result
    }

    pub fn decompress(&self, src: &[u32]) -> Vec<u8> {
        let mut dict: Vec<Vec<u8>> = Vec::with_capacity(256);
    
        for word in 0..256 {
            dict.push(vec![word as u8]);
        }
    
        let first_code = src[0];
        let mut var = dict[first_code as usize].clone();
        let mut result: Vec<u8> = var.clone();
    
        for &code in &src[1..] {
            let mut entry: Vec<u8>;
    
            if code < dict.len() as u32 {
                entry = dict[code as usize].clone();
            } else if code == dict.len() as u32 {
                entry = var.clone();
                entry.push(var[0]);
            } else {
                panic!("Error reading characters, position: {}", code);
            }
    
            result.extend(&entry);
    
            let mut new_entry: Vec<u8> = var.clone();
            new_entry.push(entry[0]);
            dict.push(new_entry);
            
            var = entry;
        }
    
        result
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
            0u32, 1, 2, 3, 4, 5, 6, 7, 8, 9,
            256, 258, 4, 259, 261, 7, 266, 269, 262, 264,
            260, 258, 259, 273, 274, 9, 3, 270, 264, 2,
            260, 5, 287, 288, 1
        ];

        assert_eq!(compressed, expected);
    }

    #[test]
    fn decompress_res() {
        let lzw = LZW::new();

        let compressed = vec![
            0u32, 1, 2, 3, 4, 5, 6, 7, 8, 9,
            256, 258, 4, 259, 261, 7, 266, 269, 262, 264,
            260, 258, 259, 273, 274, 9, 3, 270, 264, 2,
            260, 5, 287, 288, 1
        ];

        let uncompressed = lzw.decompress(&compressed);

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
