//! Cross-compiles `win-stargate` when MinGW is available (Linux CI installs `mingw-w64`).

mod common;

use common::{build_win_stargate_exe, mingw_available, TestHarness};
use std::path::Path;
use uuid::Uuid;

#[test]
fn win_stargate_make_produces_pe_exe() {
    if !mingw_available() {
        eprintln!("SKIP win_stargate_make_produces_pe_exe: x86_64-w64-mingw32-gcc not on PATH");
        return;
    }
    let h = TestHarness::new();
    let uuid = Uuid::new_v4().to_string();
    h.register_imp_secret(&uuid);

    let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
    let exe = build_win_stargate_exe(
        &repo_root,
        &h.aes_key_b64,
        "127.0.0.1",
        "4443",
        &uuid,
    )
    .expect("win-stargate build");

    let meta = std::fs::metadata(&exe).expect("stat beacon.exe");
    assert!(meta.len() > 4096, "beacon.exe unexpectedly small");
}

#[test]
fn build_imp_endpoint_returns_exe_bytes_when_mingw_present() {
    if !mingw_available() {
        eprintln!("SKIP build_imp_endpoint: MinGW not on PATH");
        return;
    }

    let rt = actix_rt::Runtime::new().unwrap();
    rt.block_on(async {
        let h = TestHarness::new();
        let token = h.operator_token().await;
        let app = h.conduit_service().await;

        let req = actix_web::test::TestRequest::post()
            .uri("/build_imp")
            .insert_header(("X-Token", token))
            .insert_header(("X-Target", "windows_stargate"))
            .insert_header(("X-Format", "exe"))
            .insert_header(("X-Target-IP", "127.0.0.1"))
            .insert_header(("X-Target-Port", "4443"))
            .insert_header(("X-TSleep", "2"))
            .insert_header(("X-Jitter", "0"))
            .to_request();
        let resp = actix_web::test::call_service(&app, req).await;
        assert!(
            resp.status().is_success(),
            "build_imp failed: {:?}",
            resp.status()
        );
        let body = actix_web::test::read_body(resp).await;
        assert!(body.len() > 4096);
        // PE magic
        assert_eq!(&body[0..2], b"MZ");
    });
}
