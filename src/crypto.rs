use crate::error::SdkError;
use libsignal_dezire::vxeddsa::{gen_keypair, vxeddsa_sign, KeyPair};
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
pub fn sign_payload(
    signing_private_key: &[u8; 32],
    payload: &[u8],
) -> Result<(String, String), SdkError> {
    let out = vxeddsa_sign(signing_private_key, payload)?;

    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let sig_b64 = STANDARD.encode(out.signature);
    let vrf_b64 = STANDARD.encode(out.vrf);

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

use libsignal_dezire::ratchet::RatchetState;
use serde::{Deserialize, Serialize};

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
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let bytes = STANDARD
        .decode(b64)
        .map_err(|e| SdkError::Crypto(format!("Base64 decode error: {}", e)))?;
    if bytes.len() != 33 {
        return Err(SdkError::Crypto(format!(
            "Invalid key length: {}",
            bytes.len()
        )));
    }
    if bytes[0] != 0x05 {
        return Err(SdkError::Crypto(
            "Invalid public key prefix, expected 0x05".to_string(),
        ));
    }
    let mut out = [0u8; 33];
    out.copy_from_slice(&bytes);
    Ok(out)
}

pub fn decode_b64_96(b64: &str) -> Result<[u8; 96], SdkError> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};
    let bytes = STANDARD
        .decode(b64)
        .map_err(|e| SdkError::Crypto(format!("Base64 decode error: {}", e)))?;
    if bytes.len() != 96 {
        return Err(SdkError::Crypto(format!(
            "Invalid sig length: {}",
            bytes.len()
        )));
    }
    let mut out = [0u8; 96];
    out.copy_from_slice(&bytes);
    Ok(out)
}

// ---------------------------------------------------------------------------
// High-Level Encryption and Decryption
// ---------------------------------------------------------------------------

use crate::messaging::{KeyStore, SessionStore};
use libsignal_dezire::ratchet::{
    decrypt as ratchet_decrypt, encrypt as ratchet_encrypt, init_receiver_state, init_sender_state,
    DhPrivateKey, DhPublicKey,
};
use libsignal_dezire::utils::decode_public_key;
use libsignal_dezire::x3dh::{
    x3dh_initiator, x3dh_responder, OneTimePreKey, PreKeyBundle, SignedPreKey,
};
use std::sync::Arc;

pub fn parse_prekey_bundle(
    identity_key_b64: &str,
    signed_pre_key_b64: &str,
    signature_b64: &str,
    opk_opt: Option<(u32, &str)>,
) -> Result<PreKeyBundle, SdkError> {
    let bundle_identity_pub = decode_b64_33(identity_key_b64)?;
    let bundle_spk_pub = decode_b64_33(signed_pre_key_b64)?;
    let bundle_sig = decode_b64_96(signature_b64)?;

    let opk = match opk_opt {
        Some((id, key_b64)) => Some(OneTimePreKey {
            id,
            public_key: decode_b64_33(key_b64)?,
        }),
        None => None,
    };

    Ok(PreKeyBundle {
        identity_key: bundle_identity_pub,
        signed_prekey: SignedPreKey {
            id: 1, // backend API doesn't return SPK id, defaults to 1
            public_key: bundle_spk_pub,
            signature: bundle_sig,
        },
        one_time_prekey: opk,
    })
}

pub fn encrypt_message(
    payload: &[u8],
    id_key: &([u8; 32], [u8; 33]),
    existing_session: Option<ActiveSession>,
    prekey_bundle_opt: Option<(String, String, PreKeyBundle)>,
) -> Result<(EncryptedPayload, ActiveSession), SdkError> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    let mut active_session;
    let mut x3dh_init_data = None;

    if let Some(session) = existing_session {
        active_session = session;
    } else {
        let (recipient_id, recipient_device_id, bundle) = prekey_bundle_opt.ok_or_else(|| {
            SdkError::Crypto("No existing session and no prekey bundle provided".into())
        })?;

        let init_result = x3dh_initiator(&id_key.0, &bundle)?;

        let spk_pub_bytes = decode_public_key(&bundle.signed_prekey.public_key)
            .map_err(|_| SdkError::Crypto("Invalid SPK pub".into()))?;
        let spk_pub = DhPublicKey::from(spk_pub_bytes);

        let ratchet_state = init_sender_state(init_result.shared_secret, spk_pub)
            .map_err(|e| SdkError::Crypto(format!("Ratchet init failed: {:?}", e)))?;

        active_session = ActiveSession {
            ratchet_state,
            remote_identity_pub: bundle.identity_key.to_vec(),
            remote_user_id: recipient_id,
            remote_device_id: recipient_device_id,
        };

        x3dh_init_data = Some((
            STANDARD.encode(id_key.1),
            STANDARD.encode(init_result.ephemeral_public),
            bundle.one_time_prekey.map(|o| o.id),
        ));
    }

    let ad = construct_ad(&id_key.1, &active_session.remote_identity_pub);

    let (enc_header, ciphertext_bytes) =
        ratchet_encrypt(&mut active_session.ratchet_state, payload, &ad)
            .map_err(|e| SdkError::Crypto(format!("Ratchet encrypt failed: {:?}", e)))?;

    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| SdkError::Crypto(e.to_string()))?
        .as_millis() as u64;

    let mut enc_payload = EncryptedPayload {
        ciphertext: STANDARD.encode(&ciphertext_bytes),
        header: STANDARD.encode(&enc_header),
        timestamp,
        identity_key: None,
        ephemeral_key: None,
        spk_id: None,
        opk_id: None,
    };

    if let Some((ik, ek, opk_id)) = x3dh_init_data {
        enc_payload.identity_key = Some(ik);
        enc_payload.ephemeral_key = Some(ek);
        enc_payload.spk_id = Some(1); // Default SPK ID
        enc_payload.opk_id = opk_id;
    }

    Ok((enc_payload, active_session))
}

pub async fn decrypt_message(
    payload_bytes: &[u8],
    sender_id: &str,
    sessions: &Arc<dyn SessionStore>,
    keystore: &Arc<dyn KeyStore>,
) -> Result<Vec<u8>, SdkError> {
    use base64::{engine::general_purpose::STANDARD, Engine as _};

    let enc_payload: EncryptedPayload = serde_json::from_slice(payload_bytes)
        .map_err(|e| SdkError::Crypto(format!("Invalid payload json: {}", e)))?;

    let is_initial = enc_payload.identity_key.is_some() && enc_payload.ephemeral_key.is_some();

    let mut active_session: ActiveSession;

    if is_initial {
        let ik_b64 = enc_payload.identity_key.as_ref().unwrap();
        let ek_b64 = enc_payload.ephemeral_key.as_ref().unwrap();

        let sender_identity_pub = decode_b64_33(ik_b64)?;
        let sender_ephemeral_pub = decode_b64_33(ek_b64)?;
        let spk_id = enc_payload.spk_id.unwrap_or(1);
        let opk_id = enc_payload.opk_id;

        let local_id_key = keystore
            .get_identity_key()
            .await?
            .ok_or_else(|| SdkError::Storage("Identity key missing".into()))?;
        let local_spk = keystore
            .get_signed_pre_key(spk_id)
            .await?
            .ok_or_else(|| SdkError::Storage("SPK missing".into()))?;

        let opk_private = if let Some(oid) = opk_id {
            keystore.consume_one_time_pre_key(oid).await?.map(|k| k.0)
        } else {
            None
        };

        let shared_secret = x3dh_responder(
            &local_id_key.0,
            &local_spk.0,
            opk_private.as_ref(),
            &sender_identity_pub,
            &sender_ephemeral_pub,
        )?;

        let spk_priv = DhPrivateKey::from(local_spk.0);
        let spk_pub_bytes = decode_public_key(&local_spk.1)
            .map_err(|_| SdkError::Crypto("Invalid SPK pub".into()))?;
        let spk_pub = DhPublicKey::from(spk_pub_bytes);

        let ratchet_state = init_receiver_state(shared_secret, (spk_priv, spk_pub));

        active_session = ActiveSession {
            ratchet_state,
            remote_identity_pub: sender_identity_pub.to_vec(),
            remote_user_id: sender_id.to_string(),
            remote_device_id: String::new(),
        };
    } else if let Some(bytes) = sessions.get_session(sender_id).await? {
        active_session = serde_json::from_slice(&bytes)
            .map_err(|e| SdkError::Storage(format!("Session deserialize error: {}", e)))?;
    } else {
        return Err(SdkError::Crypto(
            "No session found and message is not an X3DH initial".into(),
        ));
    }

    let local_id_key = keystore
        .get_identity_key()
        .await?
        .ok_or_else(|| SdkError::Storage("Identity key missing".into()))?;
    let ad = construct_ad(&active_session.remote_identity_pub, &local_id_key.1);

    let header_bytes = STANDARD
        .decode(&enc_payload.header)
        .map_err(|e| SdkError::Crypto(format!("Invalid header base64: {}", e)))?;
    let ciphertext_bytes = STANDARD
        .decode(&enc_payload.ciphertext)
        .map_err(|e| SdkError::Crypto(format!("Invalid ciphertext base64: {}", e)))?;

    let plaintext = ratchet_decrypt(
        &mut active_session.ratchet_state,
        &header_bytes,
        &ciphertext_bytes,
        &ad,
    )
    .map_err(|e| SdkError::Crypto(format!("Ratchet decrypt failed: {:?}", e)))?;

    let session_bytes = serde_json::to_vec(&active_session)
        .map_err(|e| SdkError::Storage(format!("Session serialize error: {}", e)))?;
    sessions.save_session(sender_id, &session_bytes).await?;

    Ok(plaintext)
}
