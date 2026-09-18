use crate::transport::{ApiClient, SyncBundleResponse, Event, MqttService};
use crate::crypto::{generate_registration_keys, RegistrationKeys, encrypt_message, parse_prekey_bundle};
use crate::error::SdkError;
use crate::messaging::{InboxStore, KeyStore, OutboxStore, SessionStore};
use std::sync::Arc;
use tokio::sync::mpsc;
use uuid::Uuid;

/// Configuration settings for the DeezChatz SDK client.
#[derive(Clone, Debug)]
pub struct ClientConfig {
    /// Base URL for the DeezChatz REST API (e.g. `https://api.chatz.deez.in`).
    pub rest_url: String,
    /// Hostname or IP address of the MQTT broker (e.g. `mqtt.deez.in`).
    pub mqtt_url: String,
    /// Port number for the MQTT broker (typically `8883` for TLS, `1883` for plaintext).
    pub mqtt_port: u16,
    /// Number of One-Time Pre-Keys (OPKs) to generate and upload during device registration.
    pub opk_count: u32,
    /// Whether to use TLS encryption when connecting to the MQTT broker.
    pub use_tls: bool,
}

impl ClientConfig {
    /// Returns the preset configuration for the production DeezChatz environment.
    ///
    /// - REST API: `https://api.chatz.deez.in`
    /// - MQTT Broker: `mqtt.deez.in:8883` (TLS enabled)
    /// - OPK count: 100
    pub fn production() -> Self {
        Self {
            rest_url: "https://api.chatz.deez.in".to_string(),
            mqtt_url: "mqtt.deez.in".to_string(),
            mqtt_port: 8883,
            opk_count: 100,
            use_tls: true,
        }
    }

    /// Returns the preset configuration for local development.
    ///
    /// - REST API: `http://localhost:3000`
    /// - MQTT Broker: `localhost:1883` (TLS disabled)
    /// - OPK count: 100
    pub fn development() -> Self {
        Self {
            rest_url: "http://localhost:3000".to_string(),
            mqtt_url: "localhost".to_string(),
            mqtt_port: 1883,
            opk_count: 100,
            use_tls: false,
        }
    }

    /// Loads configuration from standard environment variables with production defaults:
    ///
    /// - `DEEZCHATZ_API_URL`: REST API base URL (default: `https://api.chatz.deez.in`)
    /// - `DEEZCHATZ_MQTT_URL`: MQTT host (default: `mqtt.deez.in`)
    /// - `DEEZCHATZ_MQTT_PORT`: MQTT port (default: `8883`)
    /// - `DEEZCHATZ_OPK_COUNT`: OPK count (default: `100`)
    /// - `DEEZCHATZ_USE_TLS`: Enable TLS (`"true"`, `"1"`, or inferred from port 8883)
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

/// The main programmatic entrypoint for interacting with DeezChatz.
///
/// Encapsulates cryptographic key operations, session ratcheting, REST API calls,
/// and persistent MQTT transport.
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

/// Metadata returned upon successfully enqueueing and publishing an encrypted message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentMessage {
    /// Unique identifier (UUIDv4) assigned to the outbound message.
    pub message_id: String,
    /// The canonical recipient user ID (UUID) resolved for this message.
    pub recipient_user_id: String,
}

impl DeezChatzClient {
    /// Constructs a new [`DeezChatzClient`] instance.
    ///
    /// Requires storage backend implementations for [`KeyStore`], [`SessionStore`],
    /// [`InboxStore`], and [`OutboxStore`].
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

    /// Returns the authenticated user's ID if currently registered or connected.
    pub fn user_id(&self) -> Option<&str> {
        self.user_id.as_deref()
    }

    /// Returns the current device's ID if registered or connected.
    pub fn device_id(&self) -> Option<&str> {
        self.device_id.as_deref()
    }

    /// Registers a new device using Google OAuth 2.0 PKCE authorization code flow.
    ///
    /// Generates identity keys, signed pre-keys, and OPKs, completes the OAuth exchange
    /// with the DeezChatz backend, registers the device with cryptographically signed keys,
    /// and saves all generated keys to the [`KeyStore`].
    pub async fn register_with_pkce(
        &mut self,
        code: &str,
        code_verifier: Option<&str>,
        redirect_uri: &str,
        phone_number: &str,
    ) -> Result<(), SdkError> {
        let keys = generate_registration_keys(self.config.opk_count);

        let oauth_res = crate::oauth::register_google_pkce(
            &self.api.client,
            &self.api.base_url,
            code,
            code_verifier,
            redirect_uri,
            &keys.identity_key.public,
        )
        .await?;

        self.finalize_registration(&oauth_res.state, phone_number, keys).await
    }


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

    /// Connects to the MQTT broker for real-time messaging.
    ///
    /// Generates a time-limited VXEdDSA cryptographic password using the Signed Pre-Key,
    /// subscribes to the client's topic (`/deezchatz/{user_id}/{device_id}/#`), starts the
    /// background event loop handling inbox persistence, outbox delivery, and reconnection,
    /// and returns an asynchronous channel receiver for [`Event`]s.
    pub async fn connect(&mut self, user_id: &str, device_id: &str) -> Result<mpsc::Receiver<Event>, SdkError> {
        self.user_id = Some(user_id.to_string());
        self.device_id = Some(device_id.to_string());

        let spk = self
            .keystore
            .get_signed_pre_key(1)
            .await?
            .ok_or_else(|| SdkError::Storage("Signed Pre-Key missing from keystore".into()))?;

        let (tx, rx) = mpsc::channel(100);

        let mqtt_service = MqttService::new(
            &self.config.mqtt_url,
            self.config.mqtt_port,
            self.config.use_tls,
            user_id,
            device_id,
            &spk.0,
            tx,
            self.sessionstore.clone(),
            self.inboxstore.clone(),
            self.outboxstore.clone(),
            self.keystore.clone(),
        )?;

        self.mqtt = Some(mqtt_service);

        Ok(rx)
    }

    /// Sends an end-to-end encrypted binary payload to a recipient.
    ///
    /// If an active Double Ratchet session already exists with the recipient, the message
    /// is encrypted using the advancing ratchet keys. If no session exists, the client
    /// transparently queries the recipient's pre-key bundle from the REST API (`POST /bundle/{id}`),
    /// performs the X3DH key exchange, establishes the ratchet session, stores the session in [`SessionStore`],
    /// enqueues the encrypted message into [`OutboxStore`], and transmits it via MQTT.
    ///
    /// Returns [`SentMessage`] containing the generated `message_id` and resolved `recipient_user_id`.
    pub async fn send_message(&self, recipient_identifier: &str, payload: &[u8]) -> Result<SentMessage, SdkError> {
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

        let existing_session_bytes = self.sessionstore.get_session(recipient_identifier).await?;
        
        let existing_session = match existing_session_bytes {
            Some(bytes) => Some(serde_json::from_slice(&bytes).map_err(|e| SdkError::Storage(format!("Session deserialize error: {}", e)))?),
            None => None,
        };

        let mut prekey_bundle_opt = None;

        if existing_session.is_none() {
            let spk = self.keystore.get_signed_pre_key(1).await?.ok_or_else(|| SdkError::Storage("Missing SPK for auth".into()))?;
            let bundle = self.api.get_bundle(user_id, &spk.0, recipient_identifier).await?;
            
            let opk_opt = bundle.opk.as_ref().map(|o| (o.id, o.key.as_str()));
            let prekey_bundle = parse_prekey_bundle(&bundle.identity_key, &bundle.signed_pre_key, &bundle.signature, opk_opt)?;
            
            prekey_bundle_opt = Some((bundle.user_id, bundle.device_id, prekey_bundle));
        }

        let (enc_payload, updated_session) = encrypt_message(payload, &id_key, existing_session, prekey_bundle_opt)?;

        let recipient_id = updated_session.remote_user_id.clone();
        let recipient_device_id = updated_session.remote_device_id.clone();

        let session_bytes = serde_json::to_vec(&updated_session).map_err(|e| SdkError::Storage(format!("Session serialize error: {}", e)))?;
        self.sessionstore.save_session(recipient_identifier, &session_bytes).await?;
        if recipient_identifier != recipient_id {
            let _ = self.sessionstore.save_session(&recipient_id, &session_bytes).await;
        }

        let payload_json = serde_json::to_vec(&enc_payload).map_err(|e| SdkError::Crypto(format!("Payload serialize error: {}", e)))?;
        let message_id = Uuid::new_v4().to_string();
        let topic = format!(
            "/deezchatz/{}/{}/{}/{}",
            recipient_id, recipient_device_id, user_id, device_id
        );

        let outbox_id = self
            .outboxstore
            .save_to_outbox(&recipient_id, &message_id, &topic, &payload_json)
            .await?;

        if let Some(mqtt) = &self.mqtt {
            let _ = mqtt.send_payload(outbox_id, &topic, payload_json).await;
        }

        Ok(SentMessage {
            message_id,
            recipient_user_id: recipient_id,
        })
    }

    /// Encodes and sends a UTF-8 text message.
    ///
    /// Frames the text with the `0x00` discriminator byte before end-to-end encryption.
    pub async fn send_text_message(&self, recipient_identifier: &str, text: &str) -> Result<SentMessage, SdkError> {
        let framed = crate::messaging::encode_text_payload(text);
        self.send_message(recipient_identifier, &framed).await
    }

    /// Encodes and sends a voice audio message (e.g. raw Opus bytes).
    ///
    /// Frames the audio data with the `0x01` discriminator byte before end-to-end encryption.
    pub async fn send_voice_message(&self, recipient_identifier: &str, audio_bytes: &[u8]) -> Result<SentMessage, SdkError> {
        let framed = crate::messaging::encode_voice_payload(audio_bytes);
        self.send_message(recipient_identifier, &framed).await
    }

    /// Encodes and sends an image message with current system timestamp and optional caption.
    ///
    /// Frames the image with the `0x02` discriminator byte, 4-byte big-endian timestamp,
    /// 2-byte big-endian caption length, caption bytes, and raw image bytes.
    pub async fn send_image_message(
        &self,
        recipient_identifier: &str,
        image_bytes: &[u8],
        caption: Option<&str>,
    ) -> Result<SentMessage, SdkError> {
        use std::time::{SystemTime, UNIX_EPOCH};
        let timestamp_seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| SdkError::InvalidOperation(format!("System time error: {}", e)))?
            .as_secs() as u32;

        let caption_str = caption.unwrap_or("");
        let framed = crate::messaging::encode_image_payload(timestamp_seconds, caption_str, image_bytes);
        self.send_message(recipient_identifier, &framed).await
    }

    /// Fetches public profile and identity information for a user without consuming an OPK.
    ///
    /// Uses `GET /bundle/sync/{target_user_id}` signed with the client's Identity Key.
    pub async fn get_sync_bundle(&self, target_user_id: &str) -> Result<SyncBundleResponse, SdkError> {
        let user_id = self.user_id.as_ref().ok_or_else(|| SdkError::InvalidOperation("User ID not set".into()))?;
        let spk = self.keystore.get_signed_pre_key(1).await?.ok_or_else(|| SdkError::Storage("Missing SPK".into()))?;

        self.api.get_sync_bundle(user_id, &spk.0, target_user_id).await
    }

    /// Gracefully disconnects the MQTT transport.
    ///
    /// Waits up to 5 seconds for any pending in-flight messages to receive `PUBACK` from the
    /// broker before terminating the connection, preventing dropped outbound messages.
    pub async fn disconnect(&mut self) -> Result<(), SdkError> {
        if let Some(mqtt) = &self.mqtt {
            mqtt.disconnect().await?;
        }
        self.mqtt = None;
        Ok(())
    }
}
