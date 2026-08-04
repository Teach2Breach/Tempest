use anvil::{
    configure_conduit_routes, configure_implant_routes, crypto, generate_aes_key_material,
    init_database, User,
};
use actix_web::{test, App};
use base64::{engine::general_purpose::STANDARD, Engine as _};
use rusqlite::params;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use tempfile::TempDir;

pub struct TestHarness {
    pub _dir: TempDir,
    pub db: Arc<Mutex<rusqlite::Connection>>,
    pub aes_key: Vec<u8>,
    pub aes_key_b64: String,
}

impl TestHarness {
    pub fn new() -> Self {
        let dir = TempDir::new().expect("tempdir");
        let db_path = dir.path().join("test.db");
        let users = vec![User {
            username: "forge".into(),
            password: "forge".into(),
        }];
        let db = init_database(&db_path, &users).expect("init_database");
        let (aes_key, aes_key_b64) = generate_aes_key_material().expect("aes key");
        std::env::set_var("TEMPEST_OUTPUTS_MAX_ROWS", "0");
        Self {
            _dir: dir,
            db,
            aes_key,
            aes_key_b64,
        }
    }

    pub fn register_imp_secret(&self, secret: &str) {
        let db = self.db.lock().unwrap();
        db.execute(
            "INSERT INTO unique_identifiers (id) VALUES (?1)",
            params![secret],
        )
        .expect("insert unique identifier");
    }

    pub async fn implant_service(&self) -> impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    > {
        let db = self.db.clone();
        let aes_key_b64 = self.aes_key_b64.clone();
        test::init_service(App::new().configure(move |cfg| {
            configure_implant_routes(cfg, db.clone(), Some(aes_key_b64.clone()));
        }))
        .await
    }

    pub async fn conduit_service(&self) -> impl actix_web::dev::Service<
        actix_http::Request,
        Response = actix_web::dev::ServiceResponse,
        Error = actix_web::Error,
    > {
        let db = self.db.clone();
        let aes_key_b64 = self.aes_key_b64.clone();
        test::init_service(App::new().configure(move |cfg| {
            configure_conduit_routes(cfg, db.clone(), Some(aes_key_b64.clone()));
        }))
        .await
    }

    pub fn encrypt_json(&self, json: &str) -> String {
        crypto::encrypt_aes_cbc_urlsafe_b64(&self.aes_key, json.as_bytes())
    }

    pub async fn operator_token(&self) -> String {
        let app = self.conduit_service().await;
        let auth = STANDARD.encode("forge:forge");
        let req = test::TestRequest::post()
            .uri("/authenticate")
            .insert_header(("Authorization", format!("Basic {auth}")))
            .to_request();
        let resp = test::call_service(&app, req).await;
        assert!(resp.status().is_success(), "authenticate failed");
        let body = test::read_body(resp).await;
        String::from_utf8(body.to_vec()).expect("token utf8")
    }

    pub fn imp_count(&self) -> i64 {
        let db = self.db.lock().unwrap();
        db.query_row("SELECT COUNT(*) FROM imps", [], |r| r.get(0))
            .unwrap_or(0)
    }
}

pub fn sample_imp_info_json(uuid: &str) -> String {
    format!(
        r#"{{"session":"{uuid}","ip":"{{{{SERVER_REPLACE_IP}}}}","username":"labuser","domain":"LAB","os":"windows","imp_pid":"4242","process_name":"beacon.exe","sleep":"2"}}"#
    )
}

pub fn mingw_available() -> bool {
    std::process::Command::new("x86_64-w64-mingw32-gcc")
        .arg("--version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

pub fn build_win_stargate_exe(
    repo_root: &Path,
    aes_key_b64: &str,
    server: &str,
    port: &str,
    uuid: &str,
) -> Result<PathBuf, String> {
    let win_dir = repo_root.join("imps/win-stargate");
    if !win_dir.is_dir() {
        return Err(format!("missing {}", win_dir.display()));
    }
    let output = std::process::Command::new("make")
        .current_dir(&win_dir)
        .env("AES_KEY", aes_key_b64)
        .arg(format!("SERVER={server}"))
        .arg(format!("PORT={port}"))
        .arg("SLEEP=2")
        .arg("JITTER=0")
        .arg(format!("UUID={uuid}"))
        .arg("CPPFLAGS=-DTEMPEST_C2_TRACE=0")
        .arg("exe")
        .output()
        .map_err(|e| format!("make failed to start: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "make failed:\nstdout:\n{}\nstderr:\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ));
    }
    let exe = win_dir.join("beacon.exe");
    if !exe.is_file() {
        return Err(format!("missing artifact {}", exe.display()));
    }
    Ok(exe)
}
