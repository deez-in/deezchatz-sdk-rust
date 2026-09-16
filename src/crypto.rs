use libsignal_dezire::vxeddsa::{gen_keypair, vxeddsa_sign, KeyPair};
use crate::error::SdkError;
use std::time::{SystemTime, UNIX_EPOCH};

/// A bundle of generated keys ready for registration.
pub struct RegistrationKeys {
    pub identity_key: KeyPair,
    pub signed_pre_key: KeyPair,
    pub signed_device_key: KeyPair,
    pub opks: Vec<KeyPair>,
}

/// Generates a complete set of keys for registration.
///
/// **Signal Protocol Spec**:
/// - Generate Identity Key Pair (Curve25519)
/// - Generate Signed Pre-Key (Curve25519)
/// - Generate Signed Device Key
/// - Generate One-Time Pre-Keys (Curve25519)
pub fn generate_registration_keys(opk_count: u32) -> RegistrationKeys {
    let identity_key = gen_keypair();
    let signed_pre_key = gen_keypair();
    let signed_device_key = gen_keypair();

    let mut opks = Vec::with_capacity(opk_count as usize);
    for _ in 0..opk_count {
        opks.push(gen_keypair());
    }

    RegistrationKeys {
        identity_key,
        signed_pre_key,
        signed_device_key,
        opks,
    }
}

/// Helper to sign payloads using the signing key (for REST authentication).
pub fn sign_payload(signing_private_key: &[u8; 32], payload: &[u8]) -> Result<(String, String), SdkError> {
    let out = vxeddsa_sign(signing_private_key, payload)
        .map_err(|_| SdkError::Crypto("Failed to sign payload".to_string()))?;
    
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let sig_b64 = STANDARD.encode(&out.signature);
    let vrf_b64 = STANDARD.encode(&out.vrf);
    
    Ok((sig_b64, vrf_b64))
}

/// Generates the required Auth Headers for stateless API requests.
pub fn generate_auth_headers(
    user_id: &str,
    signing_private_key: &[u8; 32],
) -> Result<(String, String, String, String), SdkError> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| SdkError::Crypto(e.to_string()))?
        .as_secs()
        .to_string();

    let payload = format!("{}{}", user_id, timestamp);
    let (signature, vrf) = sign_payload(signing_private_key, payload.as_bytes())?;

    Ok((user_id.to_string(), timestamp, signature, vrf))
}

use serde::{Deserialize, Serialize};
use libsignal_dezire::ratchet::RatchetState;

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedPayload {
    pub ciphertext: String,
    pub header: String,
    pub timestamp: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ephemeral_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spk_id: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub opk_id: Option<u32>,
}

#[derive(Serialize, Deserialize)]
pub struct ActiveSession {
    pub ratchet_state: RatchetState,
    pub remote_identity_pub: Vec<u8>,
    pub remote_user_id: String,
    pub remote_device_id: String,
}

pub fn construct_ad(sender_id_pub: &[u8], receiver_id_pub: &[u8]) -> Vec<u8> {
    let mut ad = Vec::with_capacity(sender_id_pub.len() + receiver_id_pub.len());
    ad.extend_from_slice(sender_id_pub);
    ad.extend_from_slice(receiver_id_pub);
    ad
}

/// Helper to decode base64 strings into fixed size arrays
pub fn decode_b64_33(b64: &str) -> Result<[u8; 33], SdkError> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let bytes = STANDARD.decode(b64).map_err(|e| SdkError::Crypto(format!("Base64 decode error: {}", e)))?;
    if bytes.len() != 33 {
        return Err(SdkError::Crypto(format!("Invalid key length: {}", bytes.len())));
    }
    let mut out = [0u8; 33];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn decode_b64_96(b64: &str) -> Result<[u8; 96], SdkError> {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let bytes = STANDARD.decode(b64).map_err(|e| SdkError::Crypto(format!("Base64 decode error: {}", e)))?;
    if bytes.len() != 96 {
        return Err(SdkError::Crypto(format!("Invalid sig length: {}", bytes.len())));
    }
    let mut out = [0u8; 96];
    out.copy_from_slice(&bytes);
    Ok(out)
}
