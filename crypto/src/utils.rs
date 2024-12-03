use super::CipherError;
use super::constants::*;

pub fn load_word(src: &[u8]) -> u64 {
    assert!(src.len() == 8, "Slice length is not 8");
    
    let array: [u8; 8] = src.try_into().expect("Slice length is not 8");
    u64::from_le_bytes(array)
}

pub fn store_word(src: u64, dst: &mut [u8]) {
    assert!(dst.len() >= 8, "Slice length must be at least 8");

    let byte_array = src.to_le_bytes();
    dst[..8].copy_from_slice(&byte_array);
}

pub fn calculate_tweak(tweak: &[u8]) -> Result<Vec<u64>, CipherError> {
    if tweak.len() != TWEAK_SIZE {
        return Err(CipherError::InvalidTweakLength);
    }

    let mut dst = Vec::new();

    let word0 = load_word(&tweak[0..8]);
    let word1 = load_word(&tweak[8..16]);

    dst.push(word0);
    dst.push(word1);
    dst.push(word0 ^ word1);

    Ok(dst)
}


#[cfg(test)]
mod utils_tests {
    use super::*;

    #[test]
    #[should_panic]
    fn load_word_incorrect_size() {
        let v = vec![1,2,3,4,5,6];
        load_word(&v);
    }

    #[test]
    fn load_word_check_res() {
        let v = vec![0x1,0x1,0x1,0x4,0,0,0,0];
        let r = load_word(&v);
        assert_eq!(r, 0x4010101);
    }

    #[test]
    #[should_panic]
    fn store_word_incorrect_size() {
        let mut bytes = [0u8; 7];
        let value: u64 = 0x0807060504030201;
        
        store_word(value, &mut bytes);
    }

    #[test]
    fn store_word_check_res() {
        let mut bytes = [0u8; 8];
        let value: u64 = 0x0807060504030201;
        
        store_word(value, &mut bytes);
        let expected: [u8; 8] = [1,2,3,4,5,6,7,8];

        assert_eq!(bytes, expected);
    }

    #[test]
    fn calculate_tweak_check_error() {
        let v = vec![0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x1,0x1,0x1,0x1,0x1,0x1,0x1];
        
        let r = calculate_tweak(&v);

        assert!(r.is_err());
        assert_eq!(r.unwrap_err(), CipherError::InvalidTweakLength);
    }

    #[test]
    fn calculate_tweak_check_res() {
        let v = vec![0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x1,0x1,0x1,0x1,0x1,0x1,0x1,0x1];
        let r = calculate_tweak(&v).unwrap();

        assert_eq!(r.len(), 3, "length is not equal");
        assert_eq!(r[0], 0x0807060504030201, "r[0] incorrect");
        assert_eq!(r[1], 0x0101010101010101, "r[1] incorrect");
        assert_eq!(r[2], 0x0807060504030201 ^ 0x0101010101010101, "r[2] incorrect");
    }
}