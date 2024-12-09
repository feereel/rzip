pub mod afile;
mod utils;

use utils::get_absolute_paths;
use afile::*;

use std::fs;
use std::fs::File;
use std::io::Write;
use std::io::Read;
use std::sync::mpsc::Receiver;
use std::sync::Arc;
use std::path::Path;

use byteorder::{ByteOrder, LittleEndian};

use crypto::CipherProcessor;
use compressor::Compressor;

use std::sync::mpsc::channel;
use workerpool::Pool;
use workerpool::thunk::{Thunk, ThunkWorker};


#[derive(Debug, PartialEq)]
pub enum ArchiveError {
    CompressingEncryptedData,
    DecompressingEncryptedData,
    FileAlreadyCompressed,
    FileAlreadyDecompressed,
    FileAlreadyEncrypted,
    FileAlreadyDecrypted,
    FileNotExist,
    IncorrectFilePath,
    ErrorWithFileRead,
    ErrorWithMetadataRead,
    IncorrectFileType,
    DecompressError,
    DecryptError,
    CompressingError,
    FilePathError,
    DataWritingError,
    DifferentMagickValue,
}

const MAGICK: [u8; 8] = [0x52, 0x5a, 0x88, 0x12, 0x78, 0xf1, 0x7, 0x13];

pub struct Archiver {
    target_path: String,
    n_workers: usize,
    processor: Option<Arc<dyn CipherProcessor>>,
    compressor: Option<Arc<dyn Compressor>>,
    rx: Option<Receiver<Result<afile::ArchiveFile, ArchiveError>>>,
}

impl Archiver {
    pub fn new(target_path: &Path, n_workers: usize, compressor: Option<Arc<dyn Compressor>>, processor: Option<Arc<dyn CipherProcessor>>) -> Self {
        let target_path = fs::canonicalize(target_path).unwrap();
        let target_path = target_path.to_string_lossy().into_owned();

        
        Self {
            target_path,
            n_workers,
            processor,
            compressor,
            rx: None,
        }
    }

    pub fn zip(&mut self, output_path: &Path) -> Result<usize, ArchiveError> {
        let workers = Pool::<ThunkWorker<Result<ArchiveFile, ArchiveError>>>::new(self.n_workers);

        let target_path = Path::new(&self.target_path).to_owned();
        let paths = get_absolute_paths(&target_path).map_err(|_| ArchiveError::FilePathError)?;
        let n_jobs = paths.len();

        println!("Total files: {}", n_jobs);

        let (tx, rx) = channel();
        self.rx = Some(rx);
        for path in paths {
            let compressor = self.compressor.clone();
            let processor = self.processor.clone();
            let target_path_clone = target_path.clone();

            workers.execute_to(tx.clone(), Thunk::of(move ||{
                worker_zip(&path, &target_path_clone, compressor, processor)
            }
            ));
        }

        let without_errors = self.store_archive(output_path, n_jobs)?;
        self.rx = None;

        Ok(without_errors)
    }

    pub fn unzip(&mut self, output_dir: &Path) -> Result<usize, ArchiveError> {
        let file = File::open(&self.target_path).map_err(|_| ArchiveError::FilePathError)?;
        let (afiles_count, encrypted) = self.load_archive_header(&file)?;
        
        let workers = Pool::<ThunkWorker<Result<ArchiveFile, ArchiveError>>>::new(self.n_workers);

        let (tx, rx) = channel();
        self.rx = Some(rx);

        for _ in 0..afiles_count {
            let afile = Archiver::load_afile(&file, encrypted)?;

            let compressor = self.compressor.clone();
            let processor = self.processor.clone();

            workers.execute_to(tx.clone(), Thunk::of(move || {
                worker_unzip(afile, compressor, processor)
            }));
        }

        let without_errors = self.store_folder(output_dir, afiles_count)?;

        Ok(without_errors)
    }

    fn store_archive_header(&self, file: &File, afiles_count: usize) -> Result<(), ArchiveError> {
        let files_count = afiles_count.to_ne_bytes().to_vec();
        // println!("files_count length: {}", files_count.len());
        let encrypted: Vec<u8> = if let Some(_) = self.processor {vec![1,0,0,0,0,0,0,0]} else {vec![0,0,0,0,0,0,0,0]};
        // println!("encrypted length: {}", encrypted.len());
        // println!("magick length: {}", MAGICK.len());

        Archiver::store_data(file, &MAGICK)?;
        Archiver::store_data(file, &files_count)?;
        Archiver::store_data(file, &encrypted)?;

        Ok(())
    }

    fn load_archive_header(&mut self, mut file: &File) -> Result<(usize, bool), ArchiveError> {
        let mut buffer = [0u8; 8];
        file.read_exact(&mut buffer).map_err(|_| ArchiveError::FilePathError)?;

        // println!("Buffer: {:?}", buffer);

        if buffer != MAGICK { return Err(ArchiveError::DifferentMagickValue)};
        
        file.read_exact(&mut buffer).map_err(|_| ArchiveError::FilePathError)?;
        let files_count = LittleEndian::read_u32(&buffer) as usize;

        file.read_exact(&mut buffer).map_err(|_| ArchiveError::FilePathError)?;
        let encrypted = LittleEndian::read_u32(&buffer) != 0;

        Ok((files_count, encrypted))
    }

    fn store_afile(file: &File, afile: ArchiveFile) -> Result<(), ArchiveError> {
        let mut name: Vec<u8> = afile.rel_path.as_bytes().to_vec();
        while name.len() % 4 != 0 {
            name.push(0);
        }


        let name_length: Vec<u8> = name.len().to_ne_bytes().to_vec();
        // println!("name_length length: {}", name_length.len());
        // println!("name: {:?}", name);
        // println!("name_length: {:?}", name_length);

        let mode: Vec<u8> = afile.mode().to_ne_bytes().to_vec();
        // println!("mode length: {}", mode.len());

        let size: Vec<u8> = afile.size().to_ne_bytes().to_vec();
        // println!("size length: {}", size.len());

        let zip_size: Vec<u8> = afile.body_size().to_ne_bytes().to_vec();
        // println!("zip_size length: {}", zip_size.len());

        let compressed: Vec<u8> = if afile.is_compressed() {vec![1,0,0,0,0,0,0,0]} else {vec![0,0,0,0,0,0,0,0]};
        
        let body = afile.take_body();

        Archiver::store_data(file, &mode)?;
        Archiver::store_data(file, &size)?;
        Archiver::store_data(file, &zip_size)?;
        Archiver::store_data(file, &compressed)?;
        Archiver::store_data(file, &name_length)?;
        Archiver::store_data(file, &name)?;
        Archiver::store_data(file, &body)?;

        Ok(())
    }

    fn load_afile(mut file: &File, encrypted:bool) -> Result<ArchiveFile, ArchiveError> {
        let mut buffer = [0u8; 8];

        file.read_exact(&mut buffer).map_err(|_| ArchiveError::FilePathError)?;
        let mode = LittleEndian::read_u64(&buffer);

        // println!("mode: {}", mode);

        file.read_exact(&mut buffer).map_err(|_| ArchiveError::FilePathError)?;
        let size = LittleEndian::read_u64(&buffer) as usize;

        // println!("size: {}", size);

        file.read_exact(&mut buffer).map_err(|_| ArchiveError::FilePathError)?;
        let zip_size = LittleEndian::read_u64(&buffer) as usize;

        // println!("zip_size: {}", zip_size);
        // println!("buffer: {:?}", buffer);

        file.read_exact(&mut buffer).map_err(|_| ArchiveError::FilePathError)?;
        let compressed = LittleEndian::read_u64(&buffer) != 0;

        // println!("compressed: {}", compressed);
        // println!("buffer: {:?}", buffer);

        file.read_exact(&mut buffer).map_err(|_| ArchiveError::FilePathError)?;
        let name_length = LittleEndian::read_u64(&buffer) as usize;

        // println!("name_length: {}", name_length as u64);
        // println!("buffer: {:?}", buffer);

        let mut name_buffer = vec![0u8; name_length];
        file.read_exact(&mut name_buffer).map_err(|_| ArchiveError::FilePathError)?;
        let name = String::from_utf8_lossy(&name_buffer).to_string().trim_end_matches('\0').to_string();

        let mut body = vec![0u8; zip_size];
        file.read_exact(&mut body).map_err(|_| ArchiveError::FilePathError)?;

        Ok(ArchiveFile::new(name, compressed, encrypted, mode, size, body))

    }
    
    fn store_data(mut file: &File, data: &[u8]) -> Result<(), ArchiveError>  {
        file.write_all(data).map_err(|_| ArchiveError::DataWritingError)?;
        Ok(())
    }

    fn store_folder(&mut self, output_dir: &Path, afiles_count: usize) -> Result<usize, ArchiveError> {
        let rx = self.rx.as_mut().unwrap()
            .iter()
            .take(afiles_count);

        let mut without_errors = 0;
        
        for result in rx {
            let afile = result?;
            println!("Files unziped: {}/{}, size: {}, path: {}", without_errors, afiles_count, afile.size(), afile.rel_path);

            let output_path = output_dir.join(&afile.rel_path);

            let prefix = output_path.parent().unwrap();
            std::fs::create_dir_all(prefix).unwrap();

            let file = File::create(output_path).map_err(|_| ArchiveError::FilePathError)?;
            Archiver::store_data(&file, &afile.take_body())?;

            without_errors += 1;
        }
        
        Ok(without_errors)
    }

    fn store_archive(&mut self, output_path: &Path, afiles_count: usize) -> Result<usize, ArchiveError> {
        let file = File::create(output_path).map_err(|_| ArchiveError::FilePathError)?;

        self.store_archive_header(&file, afiles_count)?;

        let mut without_errors = 0;

        let rx = self.rx.as_mut().unwrap()
            .iter()
            .take(afiles_count);

        for result in rx {
            let afile = result?;
            println!("Files zipped: {}/{}, size: {}, path: {}", without_errors, afiles_count, afile.size(), afile.rel_path);

            Archiver::store_afile(&file, afile)?;

            without_errors += 1;
        }
        
        Ok(without_errors)
    }

}

fn worker_zip(path: &Path, base_dir: &Path, compressor: Option<Arc<dyn Compressor>>, processor: Option<Arc<dyn CipherProcessor>>) -> Result<ArchiveFile, ArchiveError> {
    let afile = ArchiveFile::from_file(&path, &base_dir)?;

    let afile = match compressor {
        Some(c) => afile.compress(c)?,
        _ => afile,
    };

    let afile = match processor {
        Some(p) => afile.encrypt(p)?,
        None => afile,
    };

    Ok(afile)
}


fn worker_unzip(afile: ArchiveFile, compressor: Option<Arc<dyn Compressor>>, processor: Option<Arc<dyn CipherProcessor>>) -> Result<ArchiveFile, ArchiveError> {

    let afile = match processor {
        Some(p)  if afile.is_encrypted() => afile.decrypt(p)?,
        _ => afile,
    };
    // println!("Decrypted: {:?}", afile.rel_path);

    let afile = match compressor {
        Some(c) if afile.is_compressed() => afile.decompress(c)?,
        _ => afile,
    };

    // println!("Decompressed: {:?}", afile.rel_path);

    Ok(afile)
}