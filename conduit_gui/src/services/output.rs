use base64::{alphabet, engine, Engine as _};
use std::fs::File;
use std::io::Write;

const CUSTOM_ENGINE: engine::GeneralPurpose = engine::GeneralPurpose::new(&alphabet::URL_SAFE, engine::general_purpose::NO_PAD);

pub fn decode_base64_urlsafe_no_pad(s: &str) -> Option<String> {
    if let Ok(bytes) = CUSTOM_ENGINE.decode(s) {
        return String::from_utf8(bytes).ok();
    }
    None
}

pub fn process_retrieved_output(raw: &str) -> Vec<String> {
    // raw may contain concatenated outputs; split into lines for UI consumption
    raw.lines().map(|l| l.to_string()).collect()
}

// Very similar to TUI logic: detect getfile, decode trailing blob, save to loot/<filename>
pub fn try_handle_getfile(decoded_output: &str) -> Option<String> {
    if decoded_output.contains("getfile") {
        // trailing token is base64 file data
        let b64 = decoded_output.split_whitespace().last()?;
        if let Ok(content) = CUSTOM_ENGINE.decode(b64) {
            // derive filename from 3rd token (full remote path), then basename, then save to loot/
            let remote = decoded_output.split_whitespace().nth(2)?;
            let filename = remote.split(['\\', '/']).last()?;
            let filename = filename.trim_end_matches(':');
            let path = format!("loot/{}", filename);
            if let Ok(mut f) = File::create(&path) {
                let _ = f.write_all(&content);
                return Some(format!("File saved to: {}", path));
            }
        }
    }
    None
}


