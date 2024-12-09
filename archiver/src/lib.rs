pub mod afile;
mod utils;

use utils::get_absolute_paths;
use afile::*;

use std::fs::File;
use std::io::Write;
use std::io::Read;
use std::iter::zip;
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
    FilePathError,
    DataWritingError,
    DifferentMagickValue,
}

const MAGICK: [u8; 8] = [0x52, 0x5a, 0x88, 0x12, 0x78, 0xf1, 0x7, 0x13];
const SKIP_COMPRESS_SIZE: usize = 1024; // 1 kb

pub struct Archiver {
    target_path: String,
    n_workers: usize,
    processor: Option<Arc<dyn CipherProcessor>>,
    compressor: Option<Arc<dyn Compressor>>,
    pub afiles: Vec<ArchiveFile>,
}

impl Archiver {
    pub fn new(target_path: &Path, n_workers: usize, compressor: Option<Arc<dyn Compressor>>, processor: Option<Arc<dyn CipherProcessor>>) -> Self {
        let target_path = target_path.to_string_lossy().into_owned();
        
        let afiles = Vec::new();
        Self {
            target_path,
            n_workers,
            processor,
            compressor,
            afiles,
        }
    }

    pub fn zip(&mut self) -> Result<usize, ArchiveError> {
        let workers = Pool::<ThunkWorker<Result<ArchiveFile, ArchiveError>>>::new(self.n_workers);

        let target_path = Path::new(&self.target_path).to_owned();
        let paths = get_absolute_paths(&target_path).map_err(|_| ArchiveError::FilePathError)?;
        let n_jobs = paths.len();

        println!("Total files: {}", n_jobs);

        let mut i = 0;
        let (tx, rx) = channel();
        for path in paths {
            let compressor = self.compressor.clone();
            let processor = self.processor.clone();
            let target_path_clone = target_path.clone();

            i += 1;
            if i % 100 == 0  {
                println!("Files sended: {}/{}", i, n_jobs);
            }

            workers.execute_to(tx.clone(), Thunk::of(move ||{
                worker_zip(&path, &target_path_clone, compressor, processor)
            }
            ));
        }

        let mut without_errors = 0;

        let afiles: Vec<ArchiveFile> = rx.iter()
            .take(n_jobs as usize)
            .filter_map(|result| {
                match result {
                    Ok(afile) => {
                        without_errors += 1;
                        println!("Files finished: {}/{}, size: {}, path: {}", without_errors, n_jobs, afile.size(), afile.rel_path);
                        Some(afile)
                    } ,
                    Err(e) => {
                        eprintln!("Error while archive ArchiveFile: {:?}", e);
                        None
                    }
                }
            })
            .collect();
        
        println!("Done");
        self.afiles.extend(afiles);

        Ok(without_errors)
    }

    pub fn unzip(&mut self) -> Result<usize, ArchiveError> {
        let workers = Pool::<ThunkWorker<Result<ArchiveFile, ArchiveError>>>::new(self.n_workers);
        let n_jobs = self.afiles.len();


        let mut i = 0;
        let (tx, rx) = channel();
        while let Some(afile) = self.afiles.pop() {
            let compressor = self.compressor.clone();
            let processor = self.processor.clone();

            println!("Files sended: {}/{}", i, n_jobs);
            i += 1;
        
            workers.execute_to(tx.clone(), Thunk::of(move || {
                worker_unzip(afile, compressor, processor)
            }));
        }

        let mut without_errors = 0;

        let afiles: Vec<ArchiveFile> = rx.iter()
            .take(n_jobs as usize)
            .filter_map(|result| {
                match result {
                    Ok(afile) => {
                        println!("Files finished: {}/{}", without_errors, n_jobs);
                        without_errors += 1;
                        Some(afile)
                    } ,
                    Err(e) => {
                        eprintln!("Error while archive ArchiveFile: {:?}", e);
                        None
                    }
                }
            })
            .collect();
        
        self.afiles.extend(afiles);

        Ok(without_errors)
    }

    fn store_archive_header(&self, file: &File) -> Result<(), ArchiveError> {
        let files_count = self.afiles.len().to_ne_bytes().to_vec();
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

    pub fn store_folder(&mut self, output_dir: &Path) -> Result<(), ArchiveError> {
        while let Some(afile) = self.afiles.pop() {
            let output_path = output_dir.join(&afile.rel_path);

            let prefix = output_path.parent().unwrap();
            std::fs::create_dir_all(prefix).unwrap();

            let file = File::create(output_path).map_err(|_| ArchiveError::FilePathError)?;
            Archiver::store_data(&file, &afile.take_body())?;
        }
        
        Ok(())
    }

    pub fn store_archive(&mut self, output_path: &Path) -> Result<(), ArchiveError> {
        let file = File::create(output_path).map_err(|_| ArchiveError::FilePathError)?;

        self.store_archive_header(&file)?;
        
        while let Some(afile) = self.afiles.pop() {
            Archiver::store_afile(&file, afile)?;
        }

        Ok(())
    }

    pub fn load_archive(&mut self) -> Result<(), ArchiveError> {
        let file = File::open(&self.target_path).map_err(|_| ArchiveError::FilePathError)?;

        // println!("file {:?} opened", self.target_path);

        let (files_count, encrypted) = self.load_archive_header(&file)?;

        // println!("files_count: {files_count}, encrypted: {encrypted}");

        for _ in 0..files_count {
            let afile = Archiver::load_afile(&file, encrypted)?;
            // println!("Readed afile: {}", afile.rel_path);
            self.afiles.push(afile);
        }

        Ok(())
    }
}

fn worker_zip(path: &Path, base_dir: &Path, compressor: Option<Arc<dyn Compressor>>, processor: Option<Arc<dyn CipherProcessor>>) -> Result<ArchiveFile, ArchiveError> {
    let afile = ArchiveFile::from_file(&path, &base_dir)?;

    // println!("Readed: {path:?}");

    let afile = match compressor {
        Some(c) => afile.compress(c)?,
        _ => afile,
    };

    // println!("Compressed: {path:?}");

    let afile = match processor {
        Some(p) => afile.encrypt(p)?,
        None => afile,
    };

    // println!("Encrypted: {path:?}");

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