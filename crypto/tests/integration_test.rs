use rand::Rng;

use std::sync::Arc;

use crypto::{
    CipherProcessor,
    CipherBlock,
    threefish256::Cipher256,
    cbc::CBCProcessor
};

#[test]
fn decrypt_encrypt_same_value() {
    let mut rng = rand::thread_rng();

    for _ in 0..100 {
        let tweak: Vec<u8> = (0..16).map(|_| rng.gen()).collect();
        let key: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        let iv: Vec<u8> = (0..32).map(|_| rng.gen()).collect();

        let cipher = Cipher256::new(&key, &tweak).unwrap();
        let block: Arc<dyn CipherBlock> = Arc::new(cipher);

        let processor = CBCProcessor::new(block, iv).unwrap();

        let plaintext_length = rng.gen_range(100..2000);
        let plaintext1: Vec<u8> = (0..plaintext_length).map(|_| rng.gen()).collect();

        let ciphertext = processor.encrypt_blocks(&plaintext1);
        let plaintext2 = processor.decrypt_blocks(&ciphertext).unwrap();

        assert_eq!(plaintext1, plaintext2);
    }
}

#[test]
fn cipher_processor_decrypt_encrypt() {
    let mut rng = rand::thread_rng();

    for _ in 0..100 {
        let tweak: Vec<u8> = (0..16).map(|_| rng.gen()).collect();
        let key: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        let iv: Vec<u8> = (0..32).map(|_| rng.gen()).collect();

        let cipher = Cipher256::new(&key, &tweak).unwrap();
        let block: Arc<dyn CipherBlock> = Arc::new(cipher);

        let cbc_processor = CBCProcessor::new(block, iv).unwrap();
        let processor: Arc<dyn CipherProcessor> = Arc::new(cbc_processor);

        let plaintext_length = rng.gen_range(100..2000);
        let plaintext1: Vec<u8> = (0..plaintext_length).map(|_| rng.gen()).collect();

        let ciphertext = processor.encrypt_blocks(&plaintext1);
        let plaintext2 = processor.decrypt_blocks(&ciphertext).unwrap();

        assert_eq!(plaintext1, plaintext2);
    }
}