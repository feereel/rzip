use archiver::*;
use std::path::Path;
use std::path::PathBuf;
use std::sync::Arc;

use crypto::{
    CipherProcessor,
    CipherBlock,
    threefish256::Cipher256,
    cbc::CBCProcessor
};

use compressor::{
    Compressor, 
    lzw::LZW
};

use rand::Rng;

const TEST_FOLDER: &str = "tests/static/";

fn get_path(path: &str) -> PathBuf {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
    manifest.join(path)
}


fn get_cbc_processor() -> CBCProcessor {
    let mut rng = rand::thread_rng();

    let tweak: Vec<u8> = (0..16).map(|_| rng.gen()).collect();
    let key: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
    let iv: Vec<u8> = (0..32).map(|_| rng.gen()).collect();

    let cipher = Cipher256::new(&key, &tweak).unwrap();
    let block: Arc<dyn CipherBlock> = Arc::new(cipher);

    let cbc = CBCProcessor::new(block, &iv).unwrap();
    
    cbc
}

#[test]
fn zip_compress_encrypt_result() {
    let compressor:Arc<dyn Compressor> = Arc::new(LZW::new());
    let processor:Arc<dyn CipherProcessor>  = Arc::new(get_cbc_processor());

    let target_path = get_path(TEST_FOLDER);
    let n_workers = 8;

    let mut archiver = Archiver::new(&target_path, n_workers, Some(compressor), Some(processor));
    let without_errors = archiver.zip().unwrap();

    assert_eq!(without_errors, 4);

    for i in 0..4 {
        assert!(archiver.afiles[i].is_compressed());
        assert!(archiver.afiles[i].is_encrypted());
    }
}
