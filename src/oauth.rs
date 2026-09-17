use base64::{Engine as _, engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD}};
use rand::RngCore;
use reqwest::Client as HttpClient;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::SdkError;

// ---------------------------------------------------------------------------
// PKCE Helpers
// ---------------------------------------------------------------------------

/// Generates a cryptographically secure random PKCE code verifier (43-128 characters).
pub fn generate_code_verifier() -> String {
    let mut bytes = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Computes the S256 code challenge from a code verifier.
pub fn generate_code_challenge(verifier: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(verifier.as_bytes());
    let hash = hasher.finalize();
    URL_SAFE_NO_PAD.encode(hash)
}

/// Helper to generate a Google OAuth 2.0 authorization URL with PKCE.
pub fn build_google_auth_url(
    client_id: &str,
    redirect_uri: &str,
    code_challenge: &str,
    scopes: &[&str],
) -> String {
    let scope_str = if scopes.is_empty() {
        "openid email profile".to_string()
    } else {
        scopes.join(" ")
    };

    format!(
        "https://accounts.google.com/o/oauth2/v2/auth?\
        client_id={}&\
        redirect_uri={}&\
        response_type=code&\
        scope={}&\
        code_challenge={}&\
        code_challenge_method=S256&\
        access_type=offline",
        urlencoding::encode(client_id),
        urlencoding::encode(redirect_uri),
        urlencoding::encode(&scope_str),
        urlencoding::encode(code_challenge)
    )
}

// ---------------------------------------------------------------------------
// Google OAuth API Requests & Structs
// ---------------------------------------------------------------------------

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct GoogleIdTokenRequest<'a> {
    id_token: &'a str,
    i_key: String,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OAuthRegisterRequest<'a> {
    code: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    code_verifier: Option<&'a str>,
    redirect_uri: &'a str,
    i_key: String,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct GoogleRegisterResponse {
    pub status: String,
    pub user_id: String,
    pub state: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub picture: Option<String>,
}

/// Phase 1 Registration via Google OAuth ID Token (`POST /register/google/id_token`)
pub async fn register_google(
    http_client: &HttpClient,
    base_url: &str,
    id_token: &str,
    i_key_pub: &[u8; 33],
) -> Result<GoogleRegisterResponse, SdkError> {
    let url = format!("{}/register/google/id_token", base_url);
    let req_body = GoogleIdTokenRequest {
        id_token,
        i_key: STANDARD.encode(i_key_pub),
    };

    let res = http_client.post(&url).json(&req_body).send().await?;
    if !res.status().is_success() {
        let err = res.text().await.unwrap_or_default();
        return Err(SdkError::Api(format!("Google ID token registration failed: {}", err)));
    }

    Ok(res.json().await?)
}

/// Phase 1 Registration via PKCE Authorization Code (`POST /register/google/pkce`)
pub async fn register_google_pkce(
    http_client: &HttpClient,
    base_url: &str,
    code: &str,
    code_verifier: Option<&str>,
    redirect_uri: &str,
    i_key_pub: &[u8; 33],
) -> Result<GoogleRegisterResponse, SdkError> {
    let url = format!("{}/register/google/pkce", base_url);
    let req_body = OAuthRegisterRequest {
        code,
        code_verifier,
        redirect_uri,
        i_key: STANDARD.encode(i_key_pub),
    };

    let res = http_client.post(&url).json(&req_body).send().await?;
    if !res.status().is_success() {
        let err = res.text().await.unwrap_or_default();
        return Err(SdkError::Api(format!("Google PKCE registration failed: {}", err)));
    }

    Ok(res.json().await?)
}
