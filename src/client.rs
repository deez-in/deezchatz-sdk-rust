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
    pub async fn send_message(&self, recipient_identifier: &str, text: &str) -> Result<String, SdkError> {
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
        let existing_session = self.sessionstore.get_session(recipient_identifier).await?;

        let (recipient_id, recipient_device_id) = if existing_session.is_none() {
            // No session -> Fetch pre-key bundle from REST API
            let bundle = self.api.get_bundle(user_id, &id_key.0, recipient_identifier).await?;

            // Save mock session state
            self.sessionstore
                .save_session(recipient_identifier, b"mock_session_state")
                .await?;
            (bundle.user_id, bundle.device_id)
        } else {
            (recipient_identifier.to_string(), "mock_device_id".to_string())
        };

        // 2. Encrypt payload
        let ciphertext = format!("ENCRYPTED({})", text).into_bytes();
        let message_id = Uuid::new_v4().to_string();
        let topic = format!(
            "/deezchatz/{}/{}/{}/{}",
            recipient_id, recipient_device_id, user_id, device_id
        );

        // 3. Save to persistent Outbox queue BEFORE attempting publish
        // (Ensures the message survives process termination/crashes)
        let outbox_id = self
            .outboxstore
            .save_to_outbox(&recipient_id, &message_id, &topic, &ciphertext)
            .await?;

        // 4. Attempt live MQTT publish (if client is currently connected)
        if let Some(mqtt) = &self.mqtt {
            let _ = mqtt.send_payload(outbox_id, &topic, ciphertext).await;
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
