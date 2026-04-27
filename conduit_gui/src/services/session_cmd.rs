//! Session command dispatch: `sendfile` / `bof` / `inject` / `runpe` use `bofload` + basename like the TUI (`conduit`).

use std::fs;
use std::path::Path;

use base64::{alphabet, engine, Engine as _};

use crate::services::api;
use crate::services::upload::pick_file;

const CUSTOM_B64: engine::GeneralPurpose =
    engine::GeneralPurpose::new(&alphabet::URL_SAFE, engine::general_purpose::NO_PAD);

fn basename(path: &str) -> Result<String, String> {
    Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_string())
        .ok_or_else(|| "Invalid file name in path".into())
}

/// Issue a session task, mirroring `conduit` TUI: file commands upload first, then `issue_task` with basename and args.
pub async fn issue_session_task(
    url: &str,
    token: &str,
    session_id: &str,
    task_text: &str,
) -> Result<(), String> {
    let args: Vec<&str> = task_text.split_whitespace().collect();
    let first = *args.first().unwrap_or(&"");
    match first {
        "sendfile" => sendfile_dispatch(&args, url, token, session_id).await,
        "bof" => bof_dispatch(&args, url, token, session_id).await,
        "inject" => inject_dispatch(&args, url, token, session_id).await,
        "runpe" => runpe_dispatch(&args, url, token, session_id).await,
        _ => api::issue_task(url, token, session_id, task_text)
            .await
            .map_err(|e| e.to_string()),
    }
}

/// `sendfile` — TUI: path + space + urlsafe b64 in the issued task.
async fn sendfile_dispatch(
    args: &[&str],
    url: &str,
    token: &str,
    session_id: &str,
) -> Result<(), String> {
    let (path_label, bytes) = if args.len() < 2 {
        let (p, b) = pick_file().ok_or("No file selected")?;
        (p.to_string_lossy().to_string(), b)
    } else {
        let p = args[1];
        let b = fs::read(p).map_err(|e| format!("read file: {e}"))?;
        (p.to_string(), b)
    };
    let b64 = CUSTOM_B64.encode(&bytes);
    let payload = format!("{path_label} {b64}");
    let x_task = format!("sendfile {payload}");
    api::issue_task(url, token, session_id, &x_task)
        .await
        .map_err(|e| e.to_string())
}

async fn bof_dispatch(
    args: &[&str],
    url: &str,
    token: &str,
    session_id: &str,
) -> Result<(), String> {
    if args.len() > 5 {
        return Err("bof: invalid argument count (max 4 after command + path)".into());
    }
    let (name, bytes) = if args.len() < 2 {
        let (p, b) = pick_file().ok_or("No file selected")?;
        let s = p.to_string_lossy().to_string();
        (basename(&s)?, b)
    } else {
        let s = args[1].to_string();
        let b = fs::read(&s).map_err(|e| format!("read file: {e}"))?;
        (basename(&s)?, b)
    };

    api::bofload(url, token, &name, bytes)
        .await
        .map_err(|e| e.to_string())?;

    let mut task = format!("bof {name}");
    for w in args.iter().skip(2) {
        task.push(' ');
        task.push_str(w);
    }
    api::issue_task(url, token, session_id, &task)
        .await
        .map_err(|e| e.to_string())
}

async fn inject_dispatch(
    args: &[&str],
    url: &str,
    token: &str,
    session_id: &str,
) -> Result<(), String> {
    if args.len() < 2 {
        return Err("usage: inject <pid> <path> (or: inject <pid> and pick a file)".into());
    }
    if args.len() > 3 {
        return Err("inject: only inject <pid> <file> (path optional — use picker for file)".into());
    }
    let pid = args[1];
    let (name, bytes) = if args.len() < 3 {
        let (p, b) = pick_file().ok_or("No file selected")?;
        let s = p.to_string_lossy().to_string();
        (basename(&s)?, b)
    } else {
        let s = args[2].to_string();
        let b = fs::read(&s).map_err(|e| format!("read file: {e}"))?;
        (basename(&s)?, b)
    };

    api::bofload(url, token, &name, bytes)
        .await
        .map_err(|e| e.to_string())?;

    let x_task = format!("inject {pid} {name}");
    api::issue_task(url, token, session_id, &x_task)
        .await
        .map_err(|e| e.to_string())
}

async fn runpe_dispatch(
    args: &[&str],
    url: &str,
    token: &str,
    session_id: &str,
) -> Result<(), String> {
    if args.len() > 3 {
        return Err("runpe: at most 3 words (command, path, extra)".into());
    }
    let (name, bytes) = if args.len() < 2 {
        let (p, b) = pick_file().ok_or("No file selected")?;
        let s = p.to_string_lossy().to_string();
        (basename(&s)?, b)
    } else {
        let s = args[1].to_string();
        let b = fs::read(&s).map_err(|e| format!("read file: {e}"))?;
        (basename(&s)?, b)
    };

    api::bofload(url, token, &name, bytes)
        .await
        .map_err(|e| e.to_string())?;

    let mut x_task = format!("runpe {name}");
    if args.len() == 3 {
        x_task.push(' ');
        x_task.push_str(args[2]);
    }
    api::issue_task(url, token, session_id, &x_task)
        .await
        .map_err(|e| e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn basename_extracts_file_name() {
        assert_eq!(basename("/a/b/c.txt").unwrap(), "c.txt");
        // Windows-style backslashes: on Unix `Path` treats the whole as one segment.
        if cfg!(windows) {
            assert_eq!(basename("C:\\temp\\x.o").unwrap(), "x.o");
        } else {
            assert_eq!(basename("/tmp/x.o").unwrap(), "x.o");
        }
    }
}
