use crate::api::{ApiClient, SyncBundleResponse};
use crate::crypto::{generate_registration_keys, RegistrationKeys};
use crate::error::SdkError;
use crate::mqtt::{Event, MqttService};
use crate::store::{InboxStore, KeyStore, OutboxStore, SessionStore};
use std::sync::Arc;
use tokio::sync::mpsc;
use uuid::Uuid;

#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub rest_url: String,
    pub mqtt_url: String,
    pub mqtt_port: u16,
    pub opk_count: u32,
    pub use_tls: bool,
}

impl ClientConfig {
    /// Default configuration pointing to the production DeezChatz infrastructure.
    pub fn production() -> Self {
        Self {
            rest_url: "https://api.chatz.deez.in".to_string(),
            mqtt_url: "mqtt.deez.in".to_string(),
            mqtt_port: 8883,
            opk_count: 100,
            use_tls: true,
        }
    }

    /// Default configuration pointing to local development Docker environment.
    pub fn development() -> Self {
        Self {
            rest_url: "http://localhost:3000".to_string(),
            mqtt_url: "localhost".to_string(),
            mqtt_port: 1883,
            opk_count: 100,
            use_tls: false,
        }
    }

    /// Load configuration from environment variables with production fallback.
    pub fn from_env() -> Self {
        let rest_url = std::env::var("DEEZCHATZ_API_URL")
            .unwrap_or_else(|_| "https://api.chatz.deez.in".to_string());
        let mqtt_url = std::env::var("DEEZCHATZ_MQTT_URL")
            .unwrap_or_else(|_| "mqtt.deez.in".to_string());
        let mqtt_port = std::env::var("DEEZCHATZ_MQTT_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(8883);
        let opk_count = std::env::var("DEEZCHATZ_OPK_COUNT")
            .ok()
            .and_then(|c| c.parse().ok())
            .unwrap_or(100);
        let use_tls = std::env::var("DEEZCHATZ_USE_TLS")
            .map(|v| v != "0" && v.to_lowercase() != "false")
            .unwrap_or(mqtt_port == 8883);

        Self {
            rest_url,
            mqtt_url,
            mqtt_port,
            opk_count,
            use_tls,
        }
    }
}

pub struct DeezChatzClient {
    config: ClientConfig,
    api: ApiClient,
    keystore: Arc<dyn KeyStore>,
    sessionstore: Arc<dyn SessionStore>,
    inboxstore: Arc<dyn InboxStore>,
    outboxstore: Arc<dyn OutboxStore>,
    user_id: Option<String>,
    device_id: Option<String>,
    mqtt: Option<MqttService>,
}

impl DeezChatzClient {
    /// Creates a new uninitialized SDK client with persistent storage providers.
    pub fn new(
        config: ClientConfig,
        keystore: Arc<dyn KeyStore>,
        sessionstore: Arc<dyn SessionStore>,
        inboxstore: Arc<dyn InboxStore>,
        outboxstore: Arc<dyn OutboxStore>,
    ) -> Self {
        let api = ApiClient::new(config.rest_url.clone());
        Self {
            config,
            api,
            keystore,
            sessionstore,
            inboxstore,
            outboxstore,
            user_id: None,
            device_id: None,
            mqtt: None,
        }
    }

    /// Complete 2-phase API registration using PKCE OAuth authorization code:
    ///
    /// 1. Generates Signal Protocol keys (Identity, Signed Pre-Key, Signed Device Key, OPKs).
    /// 2. Exchanges OAuth PKCE auth code at `POST /register/google/pkce` with the public Identity Key.
    /// 3. Signs generated keys using VXEdDSA and registers the device at `POST /register/device`.
    /// 4. Persists the private key material to the consumer's `KeyStore`.
    pub async fn register_with_pkce(
        &mut self,
        code: &str,
        code_verifier: Option<&str>,
        redirect_uri: &str,
        phone_number: &str,
    ) -> Result<(), SdkError> {
        let keys = generate_registration_keys(self.config.opk_count);

        // Phase 1: Exchange PKCE authorization code
        let oauth_res = self
            .api
            .register_google_pkce(code, code_verifier, redirect_uri, &keys.identity_key.public)
            .await?;

        // Phase 2: Upload device keys and save to keystore
        self.finalize_registration(&oauth_res.state, phone_number, keys).await
    }

    /// Complete 2-phase API registration using Google ID Token:
    ///
    /// 1. Generates Signal Protocol keys (Identity, Signed Pre-Key, Signed Device Key, OPKs).
    /// 2. Verifies ID Token at `POST /register/google/id_token`.
    /// 3. Signs generated keys and registers the device at `POST /register/device`.
    /// 4. Persists private keys to the consumer's `KeyStore`.
    pub async fn register(
        &mut self,
        id_token: &str,
        phone_number: &str,
    ) -> Result<(), SdkError> {
        let keys = generate_registration_keys(self.config.opk_count);

        // Phase 1: Google ID token exchange
        let g_res = self.api.register_google(id_token, &keys.identity_key.public).await?;

        // Phase 2: Upload device keys and save to keystore
        self.finalize_registration(&g_res.state, phone_number, keys).await
    }

    /// Internal helper to complete Phase 2 device registration and store keys.
    async fn finalize_registration(
        &mut self,
        state: &str,
        phone_number: &str,
        keys: RegistrationKeys,
    ) -> Result<(), SdkError> {
        let opks_pub: Vec<[u8; 33]> = keys.opks.iter().map(|k| k.public).collect();

        let d_res = self
            .api
            .register_device(
                state,
                phone_number,
                &keys.identity_key.secret,
                &keys.signed_pre_key.public,
                &keys.signed_device_key.public,
                &opks_pub,
            )
            .await?;

        // Persist everything to keystore
        self.keystore
            .save_identity_key(&keys.identity_key.secret, &keys.identity_key.public)
            .await?;

        self.keystore
            .save_signed_pre_key(1, &keys.signed_pre_key.secret, &keys.signed_pre_key.public)
            .await?;

        let opk_tuples: Vec<(u32, [u8; 32], [u8; 33])> = keys
            .opks
            .into_iter()
            .enumerate()
            .map(|(i, k)| (i as u32, k.secret, k.public))
            .collect();
        self.keystore.save_one_time_pre_keys(opk_tuples).await?;

        self.user_id = Some(d_res.user_id);
        self.device_id = Some(d_res.device_id);

        Ok(())
    }

    /// Initializes the background MQTT connection, returning a channel for incoming events.
    pub async fn connect(&mut self, user_id: &str, device_id: &str) -> Result<mpsc::Receiver<Event>, SdkError> {
        self.user_id = Some(user_id.to_string());
        self.device_id = Some(device_id.to_string());

        let id_key = self
            .keystore
            .get_identity_key()
            .await?
            .ok_or_else(|| SdkError::Storage("Identity key missing from keystore".into()))?;

        let (tx, rx) = mpsc::channel(100);

        let mqtt_service = MqttService::new(
            &self.config.mqtt_url,
            self.config.mqtt_port,
            user_id,
            device_id,
            &id_key.0,
            tx,
            self.sessionstore.clone(),
            self.inboxstore.clone(),
            self.outboxstore.clone(),
            self.keystore.clone(),
        )?;

        self.mqtt = Some(mqtt_service);

        Ok(rx)
    }

    /// Sends an end-to-end encrypted message to a recipient using persistent outbox queuing.
    ///
    /// - Performs X3DH Session Establishment if no active Double Ratchet session exists.
    /// - Encrypts the payload.
    /// - Saves the ciphertext immediately to persistent `OutboxStore` as 'pending'.
    /// - Attempts live MQTT publish (if connected); otherwise the entry stays queued
    ///   in the Outbox and will be automatically delivered upon reconnection.
    /// - Returns the generated unique `message_id`.
    pub async fn send_message(&self, recipient_identifier: &str, payload: &[u8]) -> Result<String, SdkError> {
        use crate::crypto::{EncryptedPayload, ActiveSession, construct_ad, decode_b64_33, decode_b64_96};
        use libsignal_dezire::x3dh::{PreKeyBundle, SignedPreKey, OneTimePreKey, x3dh_initiator};
        use libsignal_dezire::ratchet::{init_sender_state, encrypt as ratchet_encrypt};
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use std::time::{SystemTime, UNIX_EPOCH};

        let user_id = self
            .user_id
            .as_ref()
            .ok_or_else(|| SdkError::InvalidOperation("User ID not initialized (call connect first)".into()))?;
        let device_id = self
            .device_id
            .as_ref()
            .ok_or_else(|| SdkError::InvalidOperation("Device ID not initialized (call connect first)".into()))?;

        let id_key = self
            .keystore
            .get_identity_key()
            .await?
            .ok_or_else(|| SdkError::Storage("Identity key missing from keystore".into()))?;

        // 1. Check for existing Double Ratchet session
        let existing_session_bytes = self.sessionstore.get_session(recipient_identifier).await?;

        let mut active_session: ActiveSession;
        let mut x3dh_init_data = None;
        let recipient_id: String;
        let recipient_device_id: String;

        if let Some(bytes) = existing_session_bytes {
            active_session = serde_json::from_slice(&bytes).map_err(|e| SdkError::Storage(format!("Session deserialize error: {}", e)))?;
            recipient_id = active_session.remote_user_id.clone();
            recipient_device_id = active_session.remote_device_id.clone();
        } else {
            // No session -> Fetch pre-key bundle from REST API
            let bundle = self.api.get_bundle(user_id, &id_key.0, recipient_identifier).await?;
            recipient_id = bundle.user_id.clone();
            recipient_device_id = bundle.device_id.clone();

            let bundle_identity_pub = decode_b64_33(&bundle.identity_key)?;
            let bundle_spk_pub = decode_b64_33(&bundle.signed_pre_key)?;
            let bundle_sig = decode_b64_96(&bundle.signature)?;

            let opk = match &bundle.opk {
                Some(o) => Some(OneTimePreKey {
                    id: o.id,
                    public_key: decode_b64_33(&o.key)?,
                }),
                None => None,
            };

            let prekey_bundle = PreKeyBundle {
                identity_key: bundle_identity_pub,
                signed_prekey: SignedPreKey {
                    id: 1, // backend API doesn't return SPK id, defaults to 1
                    public_key: bundle_spk_pub,
                    signature: bundle_sig,
                },
                one_time_prekey: opk,
            };

            let init_result = x3dh_initiator(&id_key.0, &prekey_bundle)
                .map_err(|e| SdkError::Crypto(format!("X3DH init failed: {:?}", e)))?;

            use libsignal_dezire::utils::decode_public_key;
            use libsignal_dezire::ratchet::DhPublicKey;

            let spk_pub_bytes = decode_public_key(&bundle_spk_pub).map_err(|_| SdkError::Crypto("Invalid SPK pub".into()))?;
            let spk_pub = DhPublicKey::from(spk_pub_bytes);

            let ratchet_state = init_sender_state(init_result.shared_secret, spk_pub)
                .map_err(|e| SdkError::Crypto(format!("Ratchet init failed: {:?}", e)))?;

            active_session = ActiveSession {
                ratchet_state,
                remote_identity_pub: bundle_identity_pub.to_vec(),
                remote_user_id: recipient_id.clone(),
                remote_device_id: recipient_device_id.clone(),
            };

            x3dh_init_data = Some((
                STANDARD.encode(&id_key.1),
                STANDARD.encode(&init_result.ephemeral_public),
                bundle.opk.map(|o| o.id),
            ));
        }

        // 2. Encrypt payload
        let ad = construct_ad(&id_key.1, &active_session.remote_identity_pub);

        let (enc_header, ciphertext_bytes) = ratchet_encrypt(&mut active_session.ratchet_state, payload, &ad)
            .map_err(|e| SdkError::Crypto(format!("Ratchet encrypt failed: {:?}", e)))?;

        // Save updated state
        let session_bytes = serde_json::to_vec(&active_session).map_err(|e| SdkError::Storage(format!("Session serialize error: {}", e)))?;
        self.sessionstore.save_session(recipient_identifier, &session_bytes).await?;

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

        let payload_json = serde_json::to_vec(&enc_payload).map_err(|e| SdkError::Crypto(format!("Payload serialize error: {}", e)))?;

        let message_id = Uuid::new_v4().to_string();
        let topic = format!(
            "/deezchatz/{}/{}/{}/{}",
            recipient_id, recipient_device_id, user_id, device_id
        );

        // 3. Save to persistent Outbox queue BEFORE attempting publish
        let outbox_id = self
            .outboxstore
            .save_to_outbox(&recipient_id, &message_id, &topic, &payload_json)
            .await?;

        // 4. Attempt live MQTT publish
        if let Some(mqtt) = &self.mqtt {
            let _ = mqtt.send_payload(outbox_id, &topic, payload_json).await;
        }

        Ok(message_id)
    }

    /// Fetches read-only profile data and identity key for a contact without popping an OPK.
    pub async fn get_sync_bundle(&self, target_user_id: &str) -> Result<SyncBundleResponse, SdkError> {
        let user_id = self.user_id.as_ref().ok_or_else(|| SdkError::InvalidOperation("User ID not set".into()))?;
        let id_key = self.keystore.get_identity_key().await?.ok_or_else(|| SdkError::Storage("Missing identity key".into()))?;

        self.api.get_sync_bundle(user_id, &id_key.0, target_user_id).await
    }
}
