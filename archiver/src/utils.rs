use std::fs;
use std::path::{Path, PathBuf};
use std::io;

pub fn get_absolute_paths(dir: &Path) -> io::Result<Vec<PathBuf>> {
    let mut paths = Vec::new();

    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();

        if entry.file_type()?.is_symlink() {
            continue;
        }

        if path.is_dir() {
            paths.extend(get_absolute_paths(&path)?);
        } else {
            paths.push(fs::canonicalize(path)?);
        }
    }
    
    Ok(paths)
}

#[allow(dead_code)]
pub fn get_rel_paths(dir: &Path, base_dir: &Path) -> io::Result<Vec<PathBuf>> {
    let absolute_paths = get_absolute_paths(dir)?;
    
    let mut relative_paths = Vec::new();
    
    for abs_path in absolute_paths {
        if let Ok(rel_path) = abs_path.strip_prefix(base_dir) {
            relative_paths.push(rel_path.to_path_buf());
        }
    }

    Ok(relative_paths)
}

#[cfg(test)]
mod utils_test {
    use super::*;

    const TEST_FOLDER: &str = "tests/static/";

    fn get_path(path: &str) -> PathBuf {
        let manifest = Path::new(env!("CARGO_MANIFEST_DIR"));
        manifest.join(path)
    }

    #[test]
    fn get_absolute_paths_res() {
        let paths = get_absolute_paths(&get_path(TEST_FOLDER)).unwrap();

        let suffixes = vec!["static/file1.bin", "static/folder1/file2.bin", "static/folder1/file3.txt", "static/text/file4.txt"];

        assert_eq!(paths.len(), suffixes.len());

        let all_suffixes_present = suffixes.iter().all(|suffix| {
            paths.iter().any(|path| path.ends_with(suffix))
        });

        assert!(all_suffixes_present);

        let sym_path = "etc/passwd";
        let is_sym_absent = paths.iter().all(|path| !path.ends_with(sym_path));

        assert!(is_sym_absent);
    }

    #[test]
    fn get_rel_paths_res() {
        let base_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
        let paths = get_rel_paths(&get_path(TEST_FOLDER), &base_dir).unwrap();

        let rel_files = vec!["tests/static/file1.bin", "tests/static/folder1/file2.bin", "tests/static/folder1/file3.txt", "tests/static/text/file4.txt"];

        assert_eq!(paths.len(), rel_files.len());

        let all_rel_files_present = rel_files.iter().all(|rel_path| {
            paths.iter().any(|path| path == Path::new(rel_path))
        });

        assert!(all_rel_files_present);

        let sym_path = Path::new("etc/passwd");
        let is_sym = paths.iter().any(|path| path == sym_path);

        assert!(!is_sym);
    }
}