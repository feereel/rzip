use rand::Rng;

use compressor::Compressor;
use compressor::lzw::LZW;

use std::sync::Arc;

#[test]
fn compress_decompress_same_value() {
    let mut rng = rand::thread_rng();

    let lzw = LZW::new();

    for _ in 0..100 {
        let length = rng.gen_range(0..1000);
        let uncompressed1: Vec<u8> = (0..length).map(|_| rng.gen()).collect();

        let compressed = lzw.compress(&uncompressed1);
        let uncompressed2 = lzw.decompress(&compressed).unwrap();

        assert_eq!(uncompressed1, uncompressed2);
    }
}

#[test]
fn compress_decompress_compressor() {
    let mut rng = rand::thread_rng();

    let lzw = LZW::new();
    let lzw: Arc<dyn Compressor> = Arc::new(lzw);

    for _ in 0..5 {
        let length = rng.gen_range(100..2000);
        let uncompressed1: Vec<u8> = (0..length).map(|_| rng.gen()).collect();

        let compressed = lzw.compress(&uncompressed1);
        let uncompressed2 = lzw.decompress(&compressed).unwrap();

        assert_eq!(uncompressed1, uncompressed2);
    }
}
