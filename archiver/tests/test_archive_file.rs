use archiver::afile::*;
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
const TEST_FILE1: &str = "tests/static/file1.bin";
const TEST_FILE2: &str = "tests/static/folder1/file2.bin";
const TEST_FILE3: &str = "tests/static/folder1/file3.txt";
const TEST_TEXT: &str = "tests/static/text/file4.txt";
const TEST_SYM: &str = "tests/static/folder1/file1.sym";
const NOEXIST_FILE: &str = "tests/static/fake1.txt";

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

fn encrypt_rnd(afile: ArchiveFile) -> Result<ArchiveFile, ArchiveError> {
    let processor:Arc<dyn CipherProcessor>  = Arc::new(get_cbc_processor());

    afile.encrypt(processor)
}


#[test]
fn new_errors() {

    let afile = ArchiveFile::from_file(&get_path(NOEXIST_FILE), Path::new(env!("CARGO_MANIFEST_DIR")));
    assert!(afile.is_err());
    assert_eq!(afile.unwrap_err(), ArchiveError::FileNotExist, "Reading noexist file should return ErrorWithMetadataRead error");

    let afile = ArchiveFile::from_file(&get_path(TEST_SYM), Path::new(env!("CARGO_MANIFEST_DIR")));
    assert!(afile.is_err(), "Error not happened");
    assert_eq!(afile.unwrap_err(), ArchiveError::IncorrectFileType, "Reading symlink should return IncorrectFileType error");


    let afile = ArchiveFile::from_file(&get_path(TEST_FOLDER), Path::new(env!("CARGO_MANIFEST_DIR")));
    assert!(afile.is_err(), "Error not happened");
    assert_eq!(afile.unwrap_err(), ArchiveError::IncorrectFileType, "Reading folder should return IncorrectFileType error");


    let s = get_path(TEST_FILE1);
    let afile = ArchiveFile::from_file(&s, Path::new(env!("CARGO_MANIFEST_DIR")));
    assert!(!afile.is_err());
    assert_eq!(afile.unwrap().rel_path, TEST_FILE1);

}

#[test]
fn new_result() {
    let afile = ArchiveFile::from_file(&get_path(TEST_FILE3), Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap();
    
    assert!(afile.rel_path.ends_with(TEST_FILE3));
    assert_eq!(afile.is_compressed(), false);
    assert_eq!(afile.is_encrypted(), false);
    assert_eq!(afile.mode(), 0o100666);
    assert_eq!(afile.clone_body(), [72, 69, 108, 108, 111, 44, 32, 110, 101, 119, 32, 87, 79, 82, 76, 68, 33]);
}

#[test]
fn encrypt_errors() {
    let afile = ArchiveFile::from_file(&get_path(TEST_FILE2), Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap();

    let afile = encrypt_rnd(afile).unwrap();
    let afile = encrypt_rnd(afile);

    assert!(afile.is_err());
    assert_eq!(afile.unwrap_err(), ArchiveError::FileAlreadyEncrypted);
}


#[test]
fn encrypt_result() {
    let afile = ArchiveFile::from_file(&get_path(TEST_FILE2), Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap();
    let body_before = afile.clone_body();

    let afile = encrypt_rnd(afile).unwrap();

    assert!(afile.is_encrypted());
    assert_ne!(afile.clone_body(),body_before);
}

#[test]
fn compress_errors() {
    let afile = ArchiveFile::from_file(&get_path(TEST_TEXT), Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap();
    let lzw = LZW::new();

    let compressor:Arc<dyn Compressor>  = Arc::new(lzw);
    let processor:Arc<dyn CipherProcessor>  = Arc::new(get_cbc_processor());

    let afile = afile.encrypt(processor).unwrap();
    let er = afile.compress(compressor.clone());
    
    assert!(er.is_err());
    assert_eq!(er.unwrap_err(), ArchiveError::CompressingEncryptedData);

    let afile = ArchiveFile::from_file(&get_path(TEST_TEXT), Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap();
    let afile = afile.compress(compressor.clone()).unwrap();
    let er = afile.compress(compressor.clone());

    assert!(er.is_err());
    assert_eq!(er.unwrap_err(), ArchiveError::FileAlreadyCompressed);
}

#[test]
fn compress_result() {
    let afile = ArchiveFile::from_file(&get_path(TEST_TEXT), Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap();

    let lzw = LZW::new();
    let compressor:Arc<dyn Compressor>  = Arc::new(lzw);

    let bsize = afile.body_size();
    let afile = afile.compress(compressor.clone()).unwrap();

    assert!(afile.is_compressed());
    assert!(afile.body_size() < bsize);
}

#[test]
fn decrypt_errors() {
    let afile = ArchiveFile::from_file(&get_path(TEST_FILE2), Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap();
    let processor:Arc<dyn CipherProcessor>  = Arc::new(get_cbc_processor());

    let afile = afile.encrypt(processor.clone()).unwrap();
    let afile = afile.decrypt(processor.clone()).unwrap();
    let er = afile.decrypt(processor.clone());

    assert!(er.is_err());
    assert_eq!(er.unwrap_err(), ArchiveError::FileAlreadyDecrypted);
}

#[test]
fn decrypt_result() {
    let afile = ArchiveFile::from_file(&get_path(TEST_FILE2), Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap();
    let processor:Arc<dyn CipherProcessor>  = Arc::new(get_cbc_processor());

    let body1 = afile.clone_body();

    let afile = afile.encrypt(processor.clone()).unwrap();
    let afile = afile.decrypt(processor.clone()).unwrap();

    let body2 = afile.take_body();

    assert_eq!(body1, body2);
}

#[test]
fn decompress_errors() {
    let afile = ArchiveFile::from_file(&get_path(TEST_TEXT), Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap();
    let lzw = LZW::new();

    let compressor:Arc<dyn Compressor>  = Arc::new(lzw);
    let processor:Arc<dyn CipherProcessor>  = Arc::new(get_cbc_processor());

    let afile = afile.compress(compressor.clone()).unwrap();
    let afile = afile.encrypt(processor).unwrap();
    let er = afile.decompress(compressor.clone());
    
    assert!(er.is_err());
    assert_eq!(er.unwrap_err(), ArchiveError::DecompressingEncryptedData);

    let afile = ArchiveFile::from_file(&get_path(TEST_TEXT), Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap();
    let er = afile.decompress(compressor.clone());

    assert!(er.is_err());
    assert_eq!(er.unwrap_err(), ArchiveError::FileAlreadyDecompressed);
}

#[test]
fn decompress_result() {
    let afile = ArchiveFile::from_file(&get_path(TEST_TEXT), Path::new(env!("CARGO_MANIFEST_DIR"))).unwrap();

    let lzw = LZW::new();
    let compressor:Arc<dyn Compressor>  = Arc::new(lzw);

    let body1 = afile.clone_body();
    let afile = afile.compress(compressor.clone()).unwrap();
    let afile = afile.decompress(compressor.clone()).unwrap();

    assert!(!afile.is_compressed());
    assert_eq!(body1, afile.take_body());
}
