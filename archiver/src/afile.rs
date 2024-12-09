use std::fs;
use std::path::Path;
use std::os::unix::fs::MetadataExt;
use std::sync::Arc;

use super::ArchiveError;

use compressor::Compressor;
use crypto::CipherProcessor;

#[derive(Debug)]
pub struct ArchiveFile {
    pub rel_path: String,
    compressed: bool,
    encrypted: bool,
    mode: u64,
    size: usize,
    body: Vec<u8>,
}

impl ArchiveFile {
    pub fn from_file(path: &Path, base_dir: &Path) -> Result<Self, ArchiveError> {

        if !path.exists() { return Err(ArchiveError::FileNotExist)};

        let rel_path = path.strip_prefix(base_dir).
            map_err(|_| ArchiveError::IncorrectFilePath)?
            .to_string_lossy()
            .into_owned();

        let metadata = fs::symlink_metadata(path).map_err(|_| {ArchiveError::ErrorWithMetadataRead})?;
        if !metadata.file_type().is_file() {return Err(ArchiveError::IncorrectFileType)};

        let body: Vec<u8> = fs::read(path).map_err(|_| ArchiveError::ErrorWithFileRead)?;

        Ok(Self {
            rel_path,
            compressed: false,
            encrypted: false,
            mode: metadata.mode() as u64,
            size: metadata.len() as usize,
            body,
        })
    }

    pub fn new(rel_path: String, compressed: bool, encrypted: bool, mode: u64, size: usize, body: Vec<u8>) -> ArchiveFile {
        Self {
            rel_path,
            compressed,
            encrypted,
            mode,
            size,
            body,
        }
    }

    pub fn compress(self, compressor: Arc<dyn Compressor>) -> Result<Self, ArchiveError> {
        if self.is_encrypted() { return Err(ArchiveError::CompressingEncryptedData); }
        if self.is_compressed() { return Err(ArchiveError::FileAlreadyCompressed); }

        Ok(Self {
            compressed: true,
            body: compressor.compress(&self.body),
            ..self
        })
    }

    pub fn decompress(self, decompressor: Arc<dyn Compressor>) -> Result<Self, ArchiveError> {
        if self.is_encrypted() { return Err(ArchiveError::DecompressingEncryptedData); }
        if !self.is_compressed() { return Err(ArchiveError::FileAlreadyDecompressed); }

        let new_body = decompressor.decompress(&self.body).map_err(|_| ArchiveError::DecompressError)?;

        Ok(Self {
            compressed: false,
            body: new_body,
            ..self
        })
    }

    pub fn encrypt(self, processor: Arc<dyn CipherProcessor>) -> Result<Self, ArchiveError> {
        if self.is_encrypted() { return Err(ArchiveError::FileAlreadyEncrypted); }

        Ok(Self{
            encrypted: true,
            body: processor.encrypt_blocks(&self.body),
            ..self
        })
    }

    pub fn decrypt(self, processor: Arc<dyn CipherProcessor>) -> Result<Self, ArchiveError> {
        if !self.is_encrypted() { return Err(ArchiveError::FileAlreadyDecrypted); }

        let new_body = processor.decrypt_blocks(&self.body).map_err(|_| ArchiveError::DecryptError)?;

        Ok(Self{
            encrypted: false,
            body: new_body,
            ..self
        })
    }

    pub fn is_encrypted(&self) -> bool {
        self.encrypted
    }

    pub fn is_compressed(&self) -> bool {
        self.compressed
    }

    pub fn mode(&self) -> u64 {
        self.mode
    }

    pub fn size(&self) -> usize {
        self.size
    }

    pub fn body_size(&self) -> usize {
        self.body.len()
    }

    pub fn take_body(self) -> Vec<u8> {
        self.body
    }

    pub fn clone_body(&self) -> Vec<u8> {
        self.body.clone()
    }
}