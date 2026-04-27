use rfd::FileDialog;
use std::fs;
use std::path::PathBuf;

/// Native file dialog; returns the chosen path and file bytes.
pub fn pick_file() -> Option<(PathBuf, Vec<u8>)> {
    let path = FileDialog::new().pick_file()?;
    let bytes = fs::read(&path).ok()?;
    Some((path, bytes))
}


