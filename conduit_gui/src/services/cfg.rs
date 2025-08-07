use config::{Config, File};

pub fn load_server_port() -> Option<u16> {
    let mut settings = Config::default();
    if settings.merge(File::with_name("conduit/config")).is_ok() {
        if let Ok(port) = settings.get::<u16>("server.port") {
            return Some(port);
        }
    }
    None
}

pub fn append_port_if_missing(mut url: String, port: u16) -> String {
    if !url.contains(':') {
        url = format!("{}:{}", url, port);
    }
    url
}


