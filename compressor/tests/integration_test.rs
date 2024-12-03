use rand::Rng;

use compressor::LZW;

#[test]
fn decrypt_encrypt_same_value() {
    let mut rng = rand::thread_rng();

    let lzw = LZW::new();

    for _ in 0..100 {
        let length = rng.gen_range(100..2000);
        let uncompressed1: Vec<u8> = (0..length).map(|_| rng.gen()).collect();

        let compressed = lzw.compress(&uncompressed1);
        let uncompressed2 = lzw.decompress(&compressed);

        assert_eq!(uncompressed1, uncompressed2);
    }
}