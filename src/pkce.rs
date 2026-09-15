use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngCore;
use sha2::{Digest, Sha256};

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
