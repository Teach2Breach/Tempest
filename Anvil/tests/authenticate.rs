use actix_web::test;
mod common;

use base64::Engine as _;
use common::TestHarness;

#[actix_rt::test]
async fn operator_authenticate_and_list_imps_empty() {
    let h = TestHarness::new();
    let token = h.operator_token().await;
    let app = h.conduit_service().await;

    let req = test::TestRequest::get()
        .uri("/imps")
        .insert_header(("X-Token", token))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert!(resp.status().is_success());
    let body = test::read_body(resp).await;
    assert_eq!(body, "[]");
}

#[actix_rt::test]
async fn operator_authenticate_rejects_bad_password() {
    let h = TestHarness::new();
    let app = h.conduit_service().await;
    let auth = base64::engine::general_purpose::STANDARD.encode("forge:wrong");
    let req = test::TestRequest::post()
        .uri("/authenticate")
        .insert_header(("Authorization", format!("Basic {auth}")))
        .to_request();
    let resp = test::call_service(&app, req).await;
    assert_eq!(resp.status(), 401);
}
