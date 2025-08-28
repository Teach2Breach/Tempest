use config::{Config, File};

pub fn load_server_port() -> Option<u16> {
    // Try local config first (copied from conduit)
    let mut here = Config::default();
    if here.merge(File::with_name("config")).is_ok() {
        if let Ok(port) = here.get::<u16>("server.port") {
            return Some(port);
        }
    }
    // Try local conduit/config first
    let mut settings = Config::default();
    if settings.merge(File::with_name("conduit/config")).is_ok() {
        if let Ok(port) = settings.get::<u16>("server.port") {
            return Some(port);
        }
    }
    // Try one directory up (common when running from conduit_gui target dir)
    let mut alt = Config::default();
    if alt.merge(File::with_name("../conduit/config")).is_ok() {
        if let Ok(port) = alt.get::<u16>("server.port") {
            return Some(port);
        }
    }
    // Fallback default to conduit port 8443
    Some(8443)
}

pub fn append_port_if_missing(mut url: String, port: u16) -> String {
    if !url.contains(':') {
        url = format!("{}:{}", url, port);
    }
    url
}


