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

/// Helper to sign payloads using the identity key (for REST authentication).
pub fn sign_payload(identity_private_key: &[u8; 32], payload: &[u8]) -> Result<(String, String), SdkError> {
    let out = vxeddsa_sign(identity_private_key, payload)
        .map_err(|_| SdkError::Crypto("Failed to sign payload".to_string()))?;
    
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let sig_b64 = STANDARD.encode(&out.signature);
    let vrf_b64 = STANDARD.encode(&out.vrf);
    
    Ok((sig_b64, vrf_b64))
}

/// Generates the required Auth Headers for stateless API requests.
pub fn generate_auth_headers(
    user_id: &str,
    identity_private_key: &[u8; 32],
) -> Result<(String, String, String, String), SdkError> {
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| SdkError::Crypto(e.to_string()))?
        .as_secs()
        .to_string();

    let payload = format!("{}{}", user_id, timestamp);
    let (signature, vrf) = sign_payload(identity_private_key, payload.as_bytes())?;

    Ok((user_id.to_string(), timestamp, signature, vrf))
}
