use rfd::FileDialog;
use std::fs;

pub fn pick_file() -> Option<(String, Vec<u8>)> {
    if let Some(path) = FileDialog::new().pick_file() {
        let filename = path.file_name()?.to_string_lossy().to_string();
        let bytes = fs::read(&path).ok()?;
        Some((filename, bytes))
    } else {
        None
    }
}


