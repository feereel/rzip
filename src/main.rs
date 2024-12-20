use clap::{Arg, Command, ArgAction};
use rand::Rng;
use sha2::{Sha256, Digest};

use std::{path::Path, process, sync::Arc};

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

use archiver::{Archiver,ArchiveError};

const TWEAK: [u8; 16] = [61,76,51,71,52,61,75,88,13,7,3,1,5,241,177,23];

struct Args {
    unzip: bool,
    compressor: Option<Arc<dyn Compressor>>,
    processor: Option<Arc<dyn CipherProcessor>>,
    threads: u32,
    output: String,
    source: String,
}


fn get_cipherprocessor(key: &[u8], tweak: &[u8], iv: &[u8]) -> Arc<dyn CipherProcessor> {
    let cipher = Cipher256::new(&key, &tweak).unwrap();
    let block: Arc<dyn CipherBlock> = Arc::new(cipher);

    let cbc_processor = CBCProcessor::new(block, &iv).unwrap();
    let processor: Arc<dyn CipherProcessor> = Arc::new(cbc_processor);

    processor
}

fn get_compressor() -> Arc<dyn Compressor> {
    let compressor:Arc<dyn Compressor> = Arc::new(LZW::new());
    compressor
}

fn hash_key(key: &str) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(&key);
    let result = hasher.finalize();
    let mut hash_array = [0u8; 32];
    hash_array.copy_from_slice(&result);
    
    hash_array
}

fn get_args() -> Args {
    let matches = Command::new("File Processor")
        .about("Программа для шифрования, дешифрования и сжатия файлов")
        .arg(Arg::new("unzip")
            .short('u')
            .long("unzip")
            .action(ArgAction::SetTrue)
            .conflicts_with("compress")
            .help("Разархивировать"))
        .arg(Arg::new("compress")
            .short('C')
            .long("compress")
            .action(ArgAction::SetTrue)
            .help("Включить сжатие"))
        .arg(Arg::new("threads")
            .short('T')
            .long("threads")
            .value_parser(clap::value_parser!(u32))
            .default_value("4")
            .help("Количество потоков. По умолчанию: 4"))
        .arg(Arg::new("output")
            .short('o')
            .long("output")
            .num_args(1)
            .required(true)
            .help("Путь, куда записываются файлы"))
        .arg(Arg::new("source")
            .short('s')
            .long("source")
            .num_args(1)
            .required(true)
            .help("Путь, откуда считывается файл"))
        .arg(Arg::new("key")
            .short('k')
            .long("key")
            .num_args(1)
            .help("Ключ, используемый для шифрования"))
        .get_matches();

    let unzip = matches.get_flag("unzip");
    let threads: u32 = *matches.get_one::<u32>("threads").unwrap_or(&4);
    let output = matches.get_one::<String>("output").unwrap();
    let source = matches.get_one::<String>("source").unwrap();
    let compress = matches.get_flag("compress");
    let key = matches.get_one::<String>("key");
    
    let mut compressor = None;
    let mut processor = None;
    if compress || unzip {
        compressor = Some(get_compressor());
    }

    if let Some(k) = key {
        let mut rng = rand::thread_rng();
        let iv: Vec<u8> = (0..32).map(|_| rng.gen()).collect();
        let hash = hash_key(k);

        processor = Some(get_cipherprocessor(&hash, &TWEAK, &iv))
    }

    Args {
        unzip,
        compressor,
        threads,
        output: output.clone(),
        source: source.clone(),
        processor
    }
}

fn main() {
    let args = get_args();

    let source_path = Path::new(&args.source);
    let mut archiver = Archiver::new(
        &source_path,
        args.threads as usize,
        args.compressor,
        args.processor,
    );

    let output_path = Path::new(&args.output);

    if args.unzip {
        println!("Started unzip process...");
        match archiver.unzip(&output_path) {
            Ok(_) => {
            }
            Err(e) => {
                match e {
                    ArchiveError::DecryptError => {
                        eprintln!("Error while decompressing. Maybe your key is incorrect!");
                    },
                    _ => (),
                }
                process::exit(1);
            }
        }
    } else {
        println!("Started zip process...");
        archiver.zip(&output_path).unwrap();
    }

    println!("Process done!");
}