use actix_web::test;
mod common;

use common::{sample_imp_info_json, TestHarness};
use uuid::Uuid;

#[actix_rt::test]
async fn implant_check_in_registers_and_appears_on_imps() {
    let h = TestHarness::new();
    let secret = Uuid::new_v4().to_string();
    h.register_imp_secret(&secret);

    let app_implant = h.implant_service().await;
    let body = h.encrypt_json(&sample_imp_info_json(&secret));

    let req = test::TestRequest::post()
        .uri("/js")
        .insert_header(("X-Unique-Identifier", secret.clone()))
        .insert_header(("Content-Type", "text/plain"))
        .set_payload(body)
        .to_request();
    let resp = test::call_service(&app_implant, req).await;
    assert!(
        resp.status().is_success(),
        "check_in failed: {:?}",
        resp.status()
    );

    let session_token = test::read_body(resp).await;
    let session_token = String::from_utf8(session_token.to_vec()).expect("session token utf8");
    assert!(!session_token.is_empty());

    assert_eq!(h.imp_count(), 1);

    let op_token = h.operator_token().await;
    let app_conduit = h.conduit_service().await;
    let req = test::TestRequest::get()
        .uri("/imps")
        .insert_header(("X-Token", op_token))
        .to_request();
    let resp = test::call_service(&app_conduit, req).await;
    assert!(resp.status().is_success());
    let imps_json = test::read_body(resp).await;
    let imps_str = String::from_utf8(imps_json.to_vec()).expect("imps utf8");
    assert!(imps_str.contains("labuser"));
    assert!(imps_str.contains("windows"));
    assert!(imps_str.contains("beacon.exe"));
}

#[actix_rt::test]
async fn implant_check_in_rejects_unknown_uuid() {
    let h = TestHarness::new();
    let app = h.implant_service().await;
    let secret = Uuid::new_v4().to_string();
    let body = h.encrypt_json(&sample_imp_info_json(&secret));

    let req = test::TestRequest::post()
        .uri("/js")
        .insert_header(("X-Unique-Identifier", secret))
        .set_payload(body)
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}

#[actix_rt::test]
async fn implant_subsequent_index_updates_sleep() {
    let h = TestHarness::new();
    let secret = Uuid::new_v4().to_string();
    h.register_imp_secret(&secret);

    let app_implant = h.implant_service().await;
    let reg_body = h.encrypt_json(&sample_imp_info_json(&secret));
    let reg_req = test::TestRequest::post()
        .uri("/js")
        .insert_header(("X-Unique-Identifier", secret.clone()))
        .set_payload(reg_body)
        .to_request();
    let reg_resp = test::call_service(&app_implant, reg_req).await;
    assert!(reg_resp.status().is_success());
    let session = test::read_body(reg_resp).await;
    let session = String::from_utf8(session.to_vec())
        .expect("session")
        .trim_matches('"')
        .to_string();

    let sleep_json = r#"{"sleep":"5"}"#;
    let idx_body = h.encrypt_json(sleep_json);
    let idx_req = test::TestRequest::post()
        .uri("/index")
        .insert_header(("X-Session", session.clone()))
        .set_payload(idx_body)
        .to_request();
    let idx_resp = test::call_service(&app_implant, idx_req).await;
    assert!(
        idx_resp.status().is_success(),
        "index failed: {:?}",
        idx_resp.status()
    );
}
