use std::path::{Path, PathBuf};

fn main() {
    let absolute_path = Path::new("file.txt"); // Абсолютный путь к файлу
    let base_directory = Path::new(""); // Базовая директория

    // Получаем относительный путь
    match absolute_path.strip_prefix(base_directory) {
        Ok(relative_path) => {
            println!("Относительный путь: {:?}", relative_path);
        }
        Err(_) => {
            println!("Файл не находится в указанной директории.");
        }
    }
}