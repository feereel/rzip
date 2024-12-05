use super::{constants::*, utils::*, mix::*, CipherError, CipherBlock};

use std::sync::Arc;

#[derive(Debug)]
pub struct Cipher256 {
    t:  [u64; TWEAK_COUNT],
    ks: [[u64; NUM_WORDS256]; ROUND_KEYS_COUNT],
}

impl Cipher256 {
    /// New256 creates a new Threefish cipher with a block size of 256 bits.
    /// The key argument must be 32 bytes and the tweak argument must be 16 bytes.
    pub fn new(key: &[u8], tweak: &[u8]) -> Result<Cipher256, CipherError> {
        // Length check the provided key
        if key.len() != BLOCK_SIZE256 {
            return Err(CipherError::InvalidKeyLength);
        }

        // Load and extend the tweak value
        let t = calculate_tweak(tweak)?;


        let mut c: Cipher256 = Cipher256{
            t: t.try_into().expect("Mismatch size in tweak"),
            ks: [[0; NUM_WORDS256]; ROUND_KEYS_COUNT],
        };

        // Load and extend key
        let mut k = vec![0; NUM_WORDS256 + 1];
        k[NUM_WORDS256] = C240;
        for i in 0..NUM_WORDS256 {
            k[i] = load_word(&key[i*8..(i+1)*8]);
            k[NUM_WORDS256] ^= k[i];
        }

        for s in 0..=NUM_ROUNDS256/4 {
            for i in 0..NUM_WORDS256 {
                c.ks[s][i] = k[(s+i)%(NUM_WORDS256+1)];
                
                let last_add = if i == NUM_WORDS256 - 3 {
                    c.t[s%3]
                } else if i == NUM_WORDS256 - 2 {
                    c.t[(s+1)%3]
                } else if i == NUM_WORDS256 - 1 {
                    s as u64
                } else {
                    0
                };
                c.ks[s][i] = c.ks[s][i].wrapping_add(last_add);
            }
        }
        Ok(c)
    }
}

impl CipherBlock for Cipher256 {
    fn encrypt(&self, src: &[u8], dst: &mut [u8]) -> Result<(), CipherError> {
        if src.len() != BLOCK_SIZE256 {
            return Err(CipherError::InvalidPlaintextLength);
        }

        if dst.len() < BLOCK_SIZE256 {
            return Err(CipherError::InvalidCiphertextLength);
        }

        let mut words = Vec::new();
        for i in 0..NUM_WORDS256 {
            let word = load_word(&src[i*8..(i+1)*8]);
            words.push(word);
        }

        for d in 0..(ROUND_KEYS_COUNT-1) {
            for i in 0..NUM_WORDS256 {
                words[i] = words[i].wrapping_add(self.ks[d][i]);
            }

            for i in 0..NUM_WORDS256 {
                for j in 0..(NUM_WORDS256/2) {
                    let mix: Mix = Mix::new(d*4+i, j);
                    (words[2*j], words[2*j+1]) = mix.mix(words[2*j], words[2*j+1]);
                }
                
                (words[1], words[3]) = (words[3], words[1]);
            }
        }

        for i in 0..NUM_WORDS256 {
            words[i] = words[i].wrapping_add(self.ks[ROUND_KEYS_COUNT-1][i]);
        }
        
        for i in 0..NUM_WORDS256 {
            store_word(words[i], &mut dst[(i*8)..(i+1)*8]);
        }

        Ok(())

    }


    /// Decrypt loads ciphertext from src, decrypts it, and stores it in dst.
    fn decrypt(&self, src: &[u8], dst: &mut [u8]) -> Result<(), CipherError> {
        if src.len() != BLOCK_SIZE256 {
            return Err(CipherError::InvalidCiphertextLength);
        }

        if dst.len() < BLOCK_SIZE256 {
            return Err(CipherError::InvalidPlaintextLength);
        }

        // Load the ciphertext
        let mut words = Vec::new();
        for i in 0..NUM_WORDS256 {
            let word = load_word(&src[i*8..(i+1)*8]);
            words.push(word);
        }

        // Subtract the final round key
        for i in 0..NUM_WORDS256 {
            words[i] = words[i].wrapping_sub(self.ks[ROUND_KEYS_COUNT-1][i]);
        }

        // Perform decryption rounds
        for d in (0..ROUND_KEYS_COUNT-1).rev() {
            for i in (0..NUM_WORDS256).rev() {
                (words[1], words[3]) = (words[3], words[1]);

                for j in (0..NUM_WORDS256/2).rev() {
                    let mix = Mix::new(d*4+i, j);
                    (words[2*j], words[2*j+1]) = mix.demix(words[2*j], words[2*j+1]);
                }
            }

            for i in 0..NUM_WORDS256 {
                words[i] = words[i].wrapping_sub(self.ks[d][i]);
            }
        }
  
        for i in 0..NUM_WORDS256 {
            store_word(words[i], &mut dst[(i*8)..(i+1)*8]);
        }

        Ok(())
    }

    fn get_block_size(&self) -> usize {
        BLOCK_SIZE256
    }
}



#[cfg(test)]
mod cipher256_test {
    use super::*;

    #[test]
    fn new_errors(){
        let tweak: Vec<u8> = (0..15).collect();
        let key: Vec<u8> = (0..32).collect();

        let r = Cipher256::new(&key, &tweak);
        
        assert!(r.is_err());
        assert_eq!(r.unwrap_err(), CipherError::InvalidTweakLength);


        let tweak: Vec<u8> = (0..16).collect();
        let key: Vec<u8> = (0..31).collect();

        let r = Cipher256::new(&key, &tweak);
        
        assert!(r.is_err());
        assert_eq!(r.unwrap_err(), CipherError::InvalidKeyLength);
    }

    #[test]
    fn new_res(){
        let tweak: Vec<u8> = (0..16).collect();
        let key: Vec<u8> = (0..32).collect();
        
        let r = Cipher256::new(&key, &tweak).unwrap();


        let expected = Cipher256 { 
            t: [506097522914230528, 1084818905618843912, 578721382704613384], 
            ks: [[506097522914230528, 1590916428533074440, 2748359193942301208, 2242261671028070680], 
                [1084818905618843912, 2748359193942301208, 2820983053732684064, 2004413935125273123], 
                [1663540288323457296, 2820983053732684064, 2510511458039503650, 506097522914230530], 
                [2242261671028070680, 2510511458039503650, 1590916428533074440, 1084818905618843915], 
                [2004413935125273122, 1590916428533074440, 1663540288323457296, 1663540288323457300], 
                [506097522914230528, 1663540288323457296, 2169637811237687824, 2242261671028070685], 
                [1084818905618843912, 2169637811237687824, 3327080576646914592, 2004413935125273128], 
                [1663540288323457296, 3327080576646914592, 2583135317829886506, 506097522914230535], 
                [2242261671028070680, 2583135317829886506, 1012195045828461056, 1084818905618843920], 
                [2004413935125273122, 1012195045828461056, 2169637811237687824, 1663540288323457305], 
                [506097522914230528, 2169637811237687824, 2242261671028070680, 2242261671028070690], 
                [1084818905618843912, 2242261671028070680, 2748359193942301208, 2004413935125273133], 
                [1663540288323457296, 2748359193942301208, 3089232840744117034, 506097522914230540], 
                [2242261671028070680, 3089232840744117034, 1084818905618843912, 1084818905618843925], 
                [2004413935125273122, 1084818905618843912, 1590916428533074440, 1663540288323457310], 
                [506097522914230528, 1590916428533074440, 2748359193942301208, 2242261671028070695], 
                [1084818905618843912, 2748359193942301208, 2820983053732684064, 2004413935125273138], 
                [1663540288323457296, 2820983053732684064, 2510511458039503650, 506097522914230545], 
                [2242261671028070680, 2510511458039503650, 1590916428533074440, 1084818905618843930]]
        };

        assert_eq!(r.t, expected.t, "tweaks are incorrect");
        assert_eq!(r.ks, expected.ks, "round keys are incorrect");

    }


    #[test]
    fn encrypt_error_plaintext(){
        let tweak: Vec<u8> = (0..16).collect();
        let key: Vec<u8> = (0..32).collect();
        let plaintext: Vec<u8> = vec![
            1,2,3,4,5,6,7,8,
            1,2,3,4,5,6,7,8,
            1,2,3,4,5,6,7,8,
            1,2,3,4,5,6,7,
        ];
        let mut ciphertext: Vec<u8> = vec![0; 32];
        
        let c = Cipher256::new(&key, &tweak).unwrap();
        let r = c.encrypt(&plaintext, &mut ciphertext);

        assert!(r.is_err());
        assert_eq!(r.unwrap_err(), CipherError::InvalidPlaintextLength);
    }

    #[test]
    fn encrypt_error_ciphertext(){
        let tweak: Vec<u8> = (0..16).collect();
        let key: Vec<u8> = (0..32).collect();
        let plaintext: Vec<u8> = vec![
            1,2,3,4,5,6,7,8,
            1,2,3,4,5,6,7,8,
            1,2,3,4,5,6,7,8,
            1,2,3,4,5,6,7,8
        ];
        let mut ciphertext: Vec<u8> = vec![0; 31];
        
        let c = Cipher256::new(&key, &tweak).unwrap();
        let r = c.encrypt(&plaintext, &mut ciphertext);

        assert!(r.is_err());
        assert_eq!(r.unwrap_err(), CipherError::InvalidCiphertextLength);
    }

    #[test]
    fn encrypt_res(){
        let tweak: Vec<u8> = (0..16).collect();
        let key: Vec<u8> = (0..32).collect();
        let plaintext: Vec<u8> = vec![
            1,2,3,4,5,6,7,8,
            1,2,3,4,5,6,7,8,
            1,2,3,4,5,6,7,8,
            1,2,3,4,5,6,7,8
        ];
        let mut ciphertext: Vec<u8> = vec![0; 32];
        
        let c = Cipher256::new(&key, &tweak).unwrap();
        c.encrypt(&plaintext, &mut ciphertext).unwrap();

        let expected: Vec<u8> = vec![
            162, 60, 114, 116, 90, 143, 88, 247,
            177, 45, 1, 223, 13, 109, 60, 141,
            2, 121, 59, 127, 220, 239, 145, 172,
            1, 206, 156, 17, 129, 49, 15, 214
        ];
        
        assert_eq!(ciphertext, expected); 
    }

    #[test]
    fn decrypt_error_ciphertext(){
        let tweak: Vec<u8> = (0..16).collect();
        let key: Vec<u8> = (0..32).collect();
        let ciphertext: Vec<u8> = vec![
            1,2,3,4,5,6,7,8,
            1,2,3,4,5,6,7,8,
            1,2,3,4,5,6,7,8,
            1,2,3,4,5,6,7,
        ];
        let mut plaintext: Vec<u8> = vec![0; 32];

        let c = Cipher256::new(&key, &tweak).unwrap();
        let block: Arc<dyn CipherBlock> = Arc::new(c);
        let r = block.decrypt(&ciphertext, &mut plaintext);

        assert!(r.is_err());
        assert_eq!(r.unwrap_err(), CipherError::InvalidCiphertextLength);
    }

    #[test]
    fn decrypt_error_plaintext(){
        let tweak: Vec<u8> = (0..16).collect();
        let key: Vec<u8> = (0..32).collect();
        let ciphertext: Vec<u8> = vec![
            1,2,3,4,5,6,7,8,
            1,2,3,4,5,6,7,8,
            1,2,3,4,5,6,7,8,
            1,2,3,4,5,6,7,8,
        ];
        let mut plaintext: Vec<u8> = vec![0; 31];

        let c = Cipher256::new(&key, &tweak).unwrap();
        let block: Arc<dyn CipherBlock> = Arc::new(c);
        let r = block.decrypt(&ciphertext, &mut plaintext);

        assert!(r.is_err());
        assert_eq!(r.unwrap_err(), CipherError::InvalidPlaintextLength);
    }

    #[test]
    fn decrypt_res(){
        let tweak: Vec<u8> = (0..16).collect();
        let key: Vec<u8> = (0..32).collect();
        let ciphertext: Vec<u8> = vec![
            162, 60, 114, 116, 90, 143, 88, 247,
            177, 45, 1, 223, 13, 109, 60, 141,
            2, 121, 59, 127, 220, 239, 145, 172,
            1, 206, 156, 17, 129, 49, 15, 214
        ];
        let mut plaintext: Vec<u8> = vec![0; 32];
        
        let c = Cipher256::new(&key, &tweak).unwrap();
        let block: Arc<dyn CipherBlock> = Arc::new(c);
        block.decrypt(&ciphertext, &mut plaintext).unwrap();

        let expected: Vec<u8> = vec![
            1,2,3,4,5,6,7,8,
            1,2,3,4,5,6,7,8,
            1,2,3,4,5,6,7,8,
            1,2,3,4,5,6,7,8,
        ];

        assert_eq!(plaintext, expected); 
    }
}