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
const ZIP_PATH: &str = "tests/zip/archive.rz";
const UNZIP_DIR: &str = "tests/zip/unzip";

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
fn zip_unzip_compress_result() {
    let compressor:Arc<dyn Compressor> = Arc::new(LZW::new());

    let target_path = get_path(TEST_FOLDER);
    let n_workers = 8;

    let mut archiver = Archiver::new(&target_path, n_workers, Some(compressor.clone()), None);

    let output_path = get_path(ZIP_PATH);
    let without_errors = archiver.zip(&output_path).unwrap();

    assert_eq!(without_errors, 4);

    let target_path = get_path(ZIP_PATH);

    println!("{:?}", target_path);
    let mut archiver = Archiver::new(&target_path, n_workers, Some(compressor.clone()), None);

    let output_dir = get_path(UNZIP_DIR);
    let without_errors = archiver.unzip(&output_dir).unwrap();

    assert_eq!(without_errors, 4);
}

