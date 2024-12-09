use crate::utils::load_word;

use super::constants::*;
use super::utils::store_word;
use super::{CipherBlock,CipherError, CipherProcessor};

use std::sync::Arc;

#[derive(Clone)]
pub struct CBCProcessor {
    block: Arc<dyn CipherBlock>,
    iv: Vec<u8>,
    block_size: usize,
}

impl CBCProcessor {
    pub fn new (block: Arc<dyn CipherBlock>, iv: &[u8]) -> Result<CBCProcessor, CipherError> {
        if iv.len() != block.get_block_size() {
            return Err(CipherError::InvalidIVLength);
        }

        let cbc = CBCProcessor{
            block_size: block.get_block_size(),
            block,
            iv:iv.to_vec(),
        };

        Ok(cbc)
    }
}

impl CBCProcessor {
    fn decrypt_block(&self, s1_block: &[u8],s2_block: &[u8], dst_block: &mut [u8]) {
        self.block.decrypt(s2_block, dst_block).unwrap();

        dst_block.iter_mut()
            .zip(s1_block.iter())
            .for_each(|(x1, x2)| *x1 ^= x2);
    }

    fn encrypt_block(&self, src_block: &[u8], dst_block: &mut [u8], state: &mut [u8]) {
        state.iter_mut()
            .zip(src_block.iter())
            .for_each(|(x1, x2)| *x1 ^= x2);

        let _state = state.to_vec();

        self.block.encrypt(&_state, state).unwrap();
        dst_block.clone_from_slice(&state);
    }

    pub fn encrypt_blocks(&self, src: &[u8]) -> Vec<u8> {
        CipherProcessor::encrypt_blocks(self, src)
    }

    pub fn decrypt_blocks(&self, src: &[u8]) -> Result<Vec<u8>, CipherError>  {
        CipherProcessor::decrypt_blocks(self, src)
    }
}

impl CipherProcessor for CBCProcessor {
    fn encrypt_blocks(&self, src: &[u8]) -> Vec<u8> {
        let last_block_size = src.len() % self.block_size;
        let padding_in_last_block = self.block_size - last_block_size;
        let block_count = src.len() / self.block_size;
        let mut add_block_count = 1;
        let mut padding_size: usize  = padding_in_last_block;
        if padding_in_last_block < PADDING {
            padding_size += self.block_size;
            add_block_count += 1;
        }
        let ciphertext_size  = (block_count + add_block_count + 1) * self.block_size;

        let mut dst = vec![0u8; ciphertext_size];
        let mut state = vec![0u8; self.block_size];

        // store IV in dst
        state[..self.block_size].clone_from_slice(&self.iv);
        dst[..self.block_size].clone_from_slice(&state);

        // encrypt and store blocks except last one
        for i in 0..block_count {
            let src_block = &src[i*self.block_size..(i+1)*self.block_size];
            let dst_block= &mut dst[(i+1)*self.block_size..(i+2)*self.block_size];

            self.encrypt_block(src_block, dst_block, &mut state);
        }

        // encrypt and store last block with padding
        let mut last_src = vec![0u8; self.block_size * add_block_count];
        let src_block = &src[block_count*self.block_size..];
        if last_block_size != 0 {
            last_src[..src_block.len()].clone_from_slice(src_block);
        }
        
        last_src[src_block.len()] = 1;
        
        let offset = last_src.len() - PADDING;
        store_word(padding_size as u64, &mut last_src[offset..]);

        // encrypt and store last blocks
        for i in 0..add_block_count {
            let src_block = &last_src[i*self.block_size..(i+1)*self.block_size];
            let dst_block= &mut dst[(block_count+i+1)*self.block_size..(block_count+i+2)*self.block_size];
            
            self.encrypt_block(src_block, dst_block, &mut state);
        }

        dst
    }

    fn decrypt_blocks(&self, src: &[u8]) -> Result<Vec<u8>, CipherError> {
        let block_count = src.len() / self.block_size;

        if src.len() % self.block_size != 0 || block_count < 2 {
            return Err(CipherError::InvalidCiphertextLength);
        }
        
        if self.iv[..] != src[..self.block_size] {
            return Err(CipherError::InvalidIVArePassed);
        }

        let mut last_block = vec![0u8; self.block_size];
        let s1_block = &src[(block_count-2)*self.block_size..(block_count-1)*self.block_size];
        let s2_block = &src[(block_count-1)*self.block_size..];

        self.decrypt_block(s1_block, s2_block,&mut last_block);

        let offset = self.block_size - PADDING;
        let padding_size = load_word(&last_block[offset..]) as usize;

        let dst_size = match ((block_count - 1) * self.block_size).checked_sub(padding_size as usize) {
            Some(x) => x,
            None => return Err(CipherError::InvalidPaddingSize),
        };

        let mut dst = vec![0u8; dst_size];

        let last_block_size = dst_size % self.block_size;
        let last_block_offset = dst_size - last_block_size;

        // minus 1 here is for situation when padding_size == 32. If remove this - 1 last block of decrypted text will be zero
        let add_block_count = (padding_size-1) / self.block_size + 1;

        if padding_size > self.block_size {
            if block_count < 3 {
                return Err(CipherError::InvalidCiphertextLength);
            }

            let s2_block = s1_block;
            let s1_block = &src[(block_count-3)*self.block_size..(block_count-2)*self.block_size];

            self.decrypt_block(s1_block, s2_block,&mut last_block);
        }

        dst[last_block_offset..].clone_from_slice(&last_block[..last_block_size]);

        for i in (1..block_count-add_block_count).rev() {
            let s1_block = &src[(i-1)*self.block_size..i*self.block_size];
            let s2_block = &src[i*self.block_size..(i+1)*self.block_size];

            self.decrypt_block(s1_block, s2_block,&mut dst[(i-1)*self.block_size..i*self.block_size]);
        }


        Ok(dst)
    }

}


#[cfg(test)]
mod cbc_encrypter_test {
    use crate::threefish256::Cipher256;
    use super::*;

    #[test]
    fn new_errors(){
        let tweak: Vec<u8> = (0..16).collect();
        let key: Vec<u8> = (0..32).collect();
        let iv: Vec<u8> = (0..31).rev().collect();
        
        let c = Cipher256::new(&key, &tweak).unwrap();
        let block: Arc<dyn CipherBlock> = Arc::new(c);

        let r = CBCProcessor::new(block, &iv);

        assert!(r.is_err());
    }

    #[test]
    fn check_correct_length(){
        let tweak: Vec<u8> = (0..16).collect();
        let key: Vec<u8> = (0..32).collect();
        let iv: Vec<u8> = (0..32).rev().collect();
        
        let c = Cipher256::new(&key, &tweak).unwrap();
        let block: Arc<dyn CipherBlock> = Arc::new(c);
        let cbc = CBCProcessor::new(block, &iv).unwrap();

        let p: Vec<u8> = (0..32).collect();
        let ciphertext = cbc.encrypt_blocks(&p);
        assert_eq!(ciphertext.len(), 32 + 32 + 32,  "length of p=32 is not equal");

        let p: Vec<u8> = (0..48).collect();
        let ciphertext = cbc.encrypt_blocks(&p);
        assert_eq!(ciphertext.len(), 32 + 32 + 32,  "length of p=48 is not equal");

        let p: Vec<u8> = (0..15).collect();
        let ciphertext = cbc.encrypt_blocks(&p);
        assert_eq!(ciphertext.len(), 32 + 32,       "length of p=15 is not equal");

        let p: Vec<u8> = (0..31).collect();
        let ciphertext = cbc.encrypt_blocks(&p);
        assert_eq!(ciphertext.len(), 32 + 32 + 32,  "length of p=35 is not equal");

        let p: Vec<u8> = (0..58).collect();
        let ciphertext = cbc.encrypt_blocks(&p);
        assert_eq!(ciphertext.len(), 32 + 32 + 32 + 32,  "length of p=35 is not equal");
        
    }

    #[test]
    fn check_res(){
        let tweak: Vec<u8> = (0..16).collect();
        let key: Vec<u8> = (0..32).collect();
        let iv: Vec<u8> = (0..32).rev().collect();
        let plaintext: Vec<u8> = (0..121).rev().collect();
        
        let c = Cipher256::new(&key, &tweak).unwrap();
        let block: Arc<dyn CipherBlock> = Arc::new(c);

        let cbc = CBCProcessor::new(block, &iv).unwrap();

        let ciphertext = cbc.encrypt_blocks(&plaintext);

        let expected = vec![
            31u8,30,29,28,27,26,25,24,23,22,21,20,19,18,17,16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0,
            218,205,148,248,223,217,156,102,244,217,211,220,63,183,36,156,98,163,168,155,93,202,34,103,255,179,98,32,230,231,38,167,
            26,80,224,17,211,219,105,138,62,163,179,225,202,72,231,100,59,113,186,212,172,27,106,43,87,6,160,110,2,124,40,128,
            127,158,88,68,227,238,98,37,207,74,205,17,25,100,162,69,111,72,157,170,93,235,60,188,155,1,94,110,64,4,144,61,
            133,86,160,107,227,131,102,231,49,247,110,217,122,188,106,161,170,30,242,13,94,49,206,70,224,144,211,189,232,124,66,127,
            123,195,56,116,238,171,91,74,219,67,131,191,225,79,105,253,60,29,218,181,63,65,81,29,136,23,165,107,83,250,236,247,
        ];

        assert_eq!(ciphertext,expected);
    }
}


#[cfg(test)]
mod cbc_decrypter_test {
    use crate::threefish256::Cipher256;
    use super::*;

    #[test]
    fn check_res(){
        let tweak: Vec<u8> = (0..16).collect();
        let key: Vec<u8> = (0..32).collect();
        let iv: Vec<u8> = (0..32).rev().collect();

        let ciphertext: Vec<u8> = vec![
            31,30,29,28,27,26,25,24,23,22,21,20,19,18,17,16,15,14,13,12,11,10,9,8,7,6,5,4,3,2,1,0,
            218,205,148,248,223,217,156,102,244,217,211,220,63,183,36,156,98,163,168,155,93,202,34,103,255,179,98,32,230,231,38,167,
            26,80,224,17,211,219,105,138,62,163,179,225,202,72,231,100,59,113,186,212,172,27,106,43,87,6,160,110,2,124,40,128,
            127,158,88,68,227,238,98,37,207,74,205,17,25,100,162,69,111,72,157,170,93,235,60,188,155,1,94,110,64,4,144,61,
            133,86,160,107,227,131,102,231,49,247,110,217,122,188,106,161,170,30,242,13,94,49,206,70,224,144,211,189,232,124,66,127,
            123,195,56,116,238,171,91,74,219,67,131,191,225,79,105,253,60,29,218,181,63,65,81,29,136,23,165,107,83,250,236,247,
        ];

        let c = Cipher256::new(&key, &tweak).unwrap();
        let block: Arc<dyn CipherBlock> = Arc::new(c);
        let cbc = CBCProcessor::new(block, &iv).unwrap();

        let plaintext = cbc.decrypt_blocks(&ciphertext).unwrap();

        let expected: Vec<u8> = (0..121).rev().collect();

        assert_eq!(plaintext,expected);
    }
}