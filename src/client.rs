use crate::transport::{ApiClient, SyncBundleResponse, Event, MqttService};
use crate::crypto::{generate_registration_keys, RegistrationKeys, encrypt_message, parse_prekey_bundle};
use crate::error::SdkError;
use crate::messaging::{InboxStore, KeyStore, OutboxStore, SessionStore};
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
    pub fn production() -> Self {
        Self {
            rest_url: "https://api.chatz.deez.in".to_string(),
            mqtt_url: "mqtt.deez.in".to_string(),
            mqtt_port: 8883,
            opk_count: 100,
            use_tls: true,
        }
    }

    pub fn development() -> Self {
        Self {
            rest_url: "http://localhost:3000".to_string(),
            mqtt_url: "localhost".to_string(),
            mqtt_port: 1883,
            opk_count: 100,
            use_tls: false,
        }
    }

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SentMessage {
    pub message_id: String,
    pub recipient_user_id: String,
}

impl DeezChatzClient {
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

    pub fn user_id(&self) -> Option<&str> {
        self.user_id.as_deref()
    }

    pub fn device_id(&self) -> Option<&str> {
        self.device_id.as_deref()
    }

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

    pub async fn register(
        &mut self,
        id_token: &str,
        phone_number: &str,
    ) -> Result<(), SdkError> {
        let keys = generate_registration_keys(self.config.opk_count);

        let g_res = crate::oauth::register_google(
            &self.api.client,
            &self.api.base_url,
            id_token,
            &keys.identity_key.public,
        )
        .await?;

        self.finalize_registration(&g_res.state, phone_number, keys).await
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

    pub async fn send_text_message(&self, recipient_identifier: &str, text: &str) -> Result<SentMessage, SdkError> {
        let framed = crate::messaging::encode_text_payload(text);
        self.send_message(recipient_identifier, &framed).await
    }

    pub async fn send_voice_message(&self, recipient_identifier: &str, audio_bytes: &[u8]) -> Result<SentMessage, SdkError> {
        let framed = crate::messaging::encode_voice_payload(audio_bytes);
        self.send_message(recipient_identifier, &framed).await
    }

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

        self.send_image_message_with_timestamp(
            recipient_identifier,
            image_bytes,
            caption,
            timestamp_seconds,
        )
        .await
    }

    pub async fn send_image_message_with_timestamp(
        &self,
        recipient_identifier: &str,
        image_bytes: &[u8],
        caption: Option<&str>,
        timestamp_seconds: u32,
    ) -> Result<SentMessage, SdkError> {
        let caption_str = caption.unwrap_or("");
        let framed = crate::messaging::encode_image_payload(timestamp_seconds, caption_str, image_bytes);
        self.send_message(recipient_identifier, &framed).await
    }

    pub async fn send_payload(
        &self,
        recipient_identifier: &str,
        payload: &crate::messaging::DecodedPayload,
    ) -> Result<SentMessage, SdkError> {
        let framed = payload.encode();
        self.send_message(recipient_identifier, &framed).await
    }

    pub async fn get_sync_bundle(&self, target_user_id: &str) -> Result<SyncBundleResponse, SdkError> {
        let user_id = self.user_id.as_ref().ok_or_else(|| SdkError::InvalidOperation("User ID not set".into()))?;
        let spk = self.keystore.get_signed_pre_key(1).await?.ok_or_else(|| SdkError::Storage("Missing SPK".into()))?;

        self.api.get_sync_bundle(user_id, &spk.0, target_user_id).await
    }

    pub async fn disconnect(&mut self) -> Result<(), SdkError> {
        if let Some(mqtt) = &self.mqtt {
            mqtt.disconnect().await?;
        }
        self.mqtt = None;
        Ok(())
    }
}
