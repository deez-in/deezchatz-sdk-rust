use reqwest::{Client as HttpClient, header::{HeaderMap, HeaderValue}};
use serde::{Deserialize, Serialize};
use crate::error::SdkError;
use crate::crypto::{generate_auth_headers, sign_payload};
use base64::{Engine as _, engine::general_purpose::STANDARD};

#[derive(Clone)]
pub struct ApiClient {
    client: HttpClient,
    base_url: String,
}

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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct DeviceRegisterRequest {
    state: String,
    state_signature: String,
    state_vrf: String,
    phone: String,
    signed_pre_key: String,
    pre_key_sign: String,
    pre_key_vrf: String,
    opks: Vec<String>,
    signed_device_key: String,
    dev_key_sign: String,
    dev_key_vrf: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct DeviceRegisterResponse {
    pub status: String,
    pub user_id: String,
    pub device_id: String,
}

#[derive(Deserialize, Debug)]
#[serde(rename_all = "camelCase")]
pub struct BundleResponse {
    pub user_id: String,
    pub device_id: String,
    pub identity_key: String,
    pub signed_pre_key: String,
    pub signature: String,
    pub opk: Option<OpkResponse>,
    pub phone: Option<String>,
    pub picture: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct OpkResponse {
    pub id: u32,
    pub key: String,
}

#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct SyncBundleResponse {
    pub user_id: String,
    pub identity_key: String,
    pub picture: Option<String>,
    pub display_name: Option<String>,
}

impl ApiClient {
    pub fn new(base_url: String) -> Self {
        Self {
            client: HttpClient::new(),
            base_url,
        }
    }

    /// Helper to attach stateless signature authentication headers.
    fn auth_headers(&self, user_id: &str, identity_private: &[u8; 32]) -> Result<HeaderMap, SdkError> {
        let (uid, ts, sig, vrf) = generate_auth_headers(user_id, identity_private)?;
        let mut headers = HeaderMap::new();
        headers.insert("X-User-Id", HeaderValue::from_str(&uid).map_err(|e| SdkError::Api(e.to_string()))?);
        headers.insert("X-Timestamp", HeaderValue::from_str(&ts).map_err(|e| SdkError::Api(e.to_string()))?);
        headers.insert("X-Signature", HeaderValue::from_str(&sig).map_err(|e| SdkError::Api(e.to_string()))?);
        headers.insert("X-Vrf", HeaderValue::from_str(&vrf).map_err(|e| SdkError::Api(e.to_string()))?);
        Ok(headers)
    }

    /// Phase 1 Registration via Google OAuth ID Token (`POST /register/google/id_token`)
    pub async fn register_google(&self, id_token: &str, i_key_pub: &[u8; 33]) -> Result<GoogleRegisterResponse, SdkError> {
        let url = format!("{}/register/google/id_token", self.base_url);
        let req_body = GoogleIdTokenRequest {
            id_token,
            i_key: STANDARD.encode(i_key_pub),
        };

        let res = self.client.post(&url).json(&req_body).send().await?;
        if !res.status().is_success() {
            let err = res.text().await.unwrap_or_default();
            return Err(SdkError::Api(format!("Google ID token registration failed: {}", err)));
        }

        Ok(res.json().await?)
    }

    /// Phase 1 Registration via PKCE Authorization Code (`POST /register/google/pkce`)
    pub async fn register_google_pkce(
        &self,
        code: &str,
        code_verifier: Option<&str>,
        redirect_uri: &str,
        i_key_pub: &[u8; 33],
    ) -> Result<GoogleRegisterResponse, SdkError> {
        let url = format!("{}/register/google/pkce", self.base_url);
        let req_body = OAuthRegisterRequest {
            code,
            code_verifier,
            redirect_uri,
            i_key: STANDARD.encode(i_key_pub),
        };

        let res = self.client.post(&url).json(&req_body).send().await?;
        if !res.status().is_success() {
            let err = res.text().await.unwrap_or_default();
            return Err(SdkError::Api(format!("Google PKCE registration failed: {}", err)));
        }

        Ok(res.json().await?)
    }

    /// Phase 2 Registration: Device registration with signed keys (`POST /register/device`)
    pub async fn register_device(
        &self,
        state: &str,
        phone: &str,
        identity_private: &[u8; 32],
        signed_pre_key_pub: &[u8; 33],
        signed_device_key_pub: &[u8; 33],
        opks_pub: &[[u8; 33]],
    ) -> Result<DeviceRegisterResponse, SdkError> {
        let url = format!("{}/register/device", self.base_url);

        let (state_signature, state_vrf) = sign_payload(identity_private, state.as_bytes())?;
        
        let spk_b64 = STANDARD.encode(signed_pre_key_pub);
        let (pre_key_sign, pre_key_vrf) = sign_payload(identity_private, spk_b64.as_bytes())?;

        let sdk_b64 = STANDARD.encode(signed_device_key_pub);
        let (dev_key_sign, dev_key_vrf) = sign_payload(identity_private, sdk_b64.as_bytes())?;

        let opks_b64: Vec<String> = opks_pub.iter().map(|k| STANDARD.encode(k)).collect();

        let req_body = DeviceRegisterRequest {
            state: state.to_string(),
            state_signature,
            state_vrf,
            phone: phone.to_string(),
            signed_pre_key: spk_b64,
            pre_key_sign,
            pre_key_vrf,
            opks: opks_b64,
            signed_device_key: sdk_b64,
            dev_key_sign,
            dev_key_vrf,
        };

        let res = self.client.post(&url).json(&req_body).send().await?;
        if !res.status().is_success() {
            let err = res.text().await.unwrap_or_default();
            return Err(SdkError::Api(format!("Device registration failed: {}", err)));
        }

        Ok(res.json().await?)
    }

    /// Fetch a pre-key bundle for a contact (`POST /bundle/{identifier}`)
    /// Atomically consumes one One-Time Pre-Key (OPK).
    pub async fn get_bundle(
        &self,
        user_id: &str,
        identity_private: &[u8; 32],
        identifier: &str,
    ) -> Result<BundleResponse, SdkError> {
        let url = format!("{}/bundle/{}", self.base_url, urlencoding::encode(identifier));
        let headers = self.auth_headers(user_id, identity_private)?;

        let res = self.client.post(&url).headers(headers).send().await?;
        if !res.status().is_success() {
            let err = res.text().await.unwrap_or_default();
            return Err(SdkError::Api(format!("Failed to fetch bundle: {}", err)));
        }

        Ok(res.json().await?)
    }

    /// Fetch read-only contact identity and profile without popping an OPK (`GET /bundle/sync/{userId}`)
    pub async fn get_sync_bundle(
        &self,
        user_id: &str,
        identity_private: &[u8; 32],
        target_user_id: &str,
    ) -> Result<SyncBundleResponse, SdkError> {
        let url = format!("{}/bundle/sync/{}", self.base_url, urlencoding::encode(target_user_id));
        let headers = self.auth_headers(user_id, identity_private)?;

        let res = self.client.get(&url).headers(headers).send().await?;
        if !res.status().is_success() {
            let err = res.text().await.unwrap_or_default();
            return Err(SdkError::Api(format!("Failed to fetch sync bundle: {}", err)));
        }

        Ok(res.json().await?)
    }
}
