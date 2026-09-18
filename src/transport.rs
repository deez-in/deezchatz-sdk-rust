use base64::{engine::general_purpose::STANDARD, Engine as _};
use reqwest::{
    header::{HeaderMap, HeaderValue},
    Client as HttpClient,
};
use rumqttc::{AsyncClient, Event as MqttEvent, Incoming, MqttOptions, QoS, Transport};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::instrument;

use crate::crypto::{decrypt_message, generate_auth_headers, sign_payload};
use crate::error::SdkError;
use crate::messaging::{InboxStore, KeyStore, OutboxStore, SessionStore};

// ---------------------------------------------------------------------------
// HTTP API Client
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct ApiClient {
    pub client: HttpClient,
    pub base_url: String,
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
    fn auth_headers(
        &self,
        user_id: &str,
        signing_private_key: &[u8; 32],
    ) -> Result<HeaderMap, SdkError> {
        let (uid, ts, sig, vrf) = generate_auth_headers(user_id, signing_private_key)?;
        let mut headers = HeaderMap::new();
        headers.insert(
            "X-User-Id",
            HeaderValue::from_str(&uid).map_err(|e| SdkError::Api(e.to_string()))?,
        );
        headers.insert(
            "X-Timestamp",
            HeaderValue::from_str(&ts).map_err(|e| SdkError::Api(e.to_string()))?,
        );
        headers.insert(
            "X-Signature",
            HeaderValue::from_str(&sig).map_err(|e| SdkError::Api(e.to_string()))?,
        );
        headers.insert(
            "X-Vrf",
            HeaderValue::from_str(&vrf).map_err(|e| SdkError::Api(e.to_string()))?,
        );
        Ok(headers)
    }

    /// Phase 2 Registration: Device registration with signed keys (`POST /register/device`)
    #[instrument(level = "debug", skip_all, err)]
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
        let (pre_key_sign, pre_key_vrf) = sign_payload(identity_private, signed_pre_key_pub)?;

        let sdk_b64 = STANDARD.encode(signed_device_key_pub);
        let (dev_key_sign, dev_key_vrf) = sign_payload(identity_private, signed_device_key_pub)?;

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
            return Err(SdkError::Api(format!(
                "Device registration failed: {}",
                err
            )));
        }

        Ok(res.json().await?)
    }

    /// Fetch a pre-key bundle for a contact (`POST /bundle/{identifier}`)
    /// Atomically consumes one One-Time Pre-Key (OPK).
    #[instrument(level = "debug", skip_all, err)]
    pub async fn get_bundle(
        &self,
        user_id: &str,
        signing_private_key: &[u8; 32],
        identifier: &str,
    ) -> Result<BundleResponse, SdkError> {
        let url = format!(
            "{}/bundle/{}",
            self.base_url,
            urlencoding::encode(identifier)
        );
        let headers = self.auth_headers(user_id, signing_private_key)?;

        let res = self.client.post(&url).headers(headers).send().await?;
        if !res.status().is_success() {
            let err = res.text().await.unwrap_or_default();
            return Err(SdkError::Api(format!("Failed to fetch bundle: {}", err)));
        }

        Ok(res.json().await?)
    }

    /// Fetch read-only contact identity and profile without popping an OPK (`GET /bundle/sync/{userId}`)
    #[instrument(level = "debug", skip_all, err)]
    pub async fn get_sync_bundle(
        &self,
        user_id: &str,
        signing_private_key: &[u8; 32],
        target_user_id: &str,
    ) -> Result<SyncBundleResponse, SdkError> {
        let url = format!(
            "{}/bundle/sync/{}",
            self.base_url,
            urlencoding::encode(target_user_id)
        );
        let headers = self.auth_headers(user_id, signing_private_key)?;

        let res = self.client.get(&url).headers(headers).send().await?;
        if !res.status().is_success() {
            let err = res.text().await.unwrap_or_default();
            return Err(SdkError::Api(format!(
                "Failed to fetch sync bundle: {}",
                err
            )));
        }

        Ok(res.json().await?)
    }
}

// ---------------------------------------------------------------------------
// MQTT Real-Time Transport
// ---------------------------------------------------------------------------

/// Real-time events emitted by the SDK
#[derive(Debug, Clone)]
pub enum Event {
    Connected,
    Disconnected,
    MessageReceived { sender: String, plaintext: Vec<u8> },
}

pub struct MqttService {
    client: AsyncClient,
    outbox_store: Arc<dyn OutboxStore>,
    inflight_messages: Arc<AtomicUsize>,
}

fn generate_mqtt_password(user_id: &str, signing_key: &[u8; 32]) -> Result<String, SdkError> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| SdkError::Mqtt(e.to_string()))?
        .as_secs()
        .to_string();

    let payload = format!("{}{}", user_id, ts);
    let (sig, vrf) = sign_payload(signing_key, payload.as_bytes())?;
    Ok(format!("{}{}{}", sig, vrf, ts))
}

pub struct MqttConfig<'a> {
    pub broker_url: &'a str,
    pub broker_port: u16,
    pub use_tls: bool,
    pub user_id: &'a str,
    pub device_id: &'a str,
    pub signed_pre_key_private: &'a [u8; 32],
    pub event_sender: tokio::sync::mpsc::Sender<Event>,
}

async fn process_message(
    topic: &str,
    payload: &[u8],
    inbox_id: Option<i64>,
    inbox: &Arc<dyn InboxStore>,
    sessions: &Arc<dyn SessionStore>,
    keystore: &Arc<dyn KeyStore>,
    event_sender: &tokio::sync::mpsc::Sender<Event>,
) {
    let parts: Vec<&str> = topic.split('/').collect();
    if parts.len() >= 6 {
        let sender_id = parts[4].to_string();

        match decrypt_message(payload, &sender_id, sessions, keystore).await {
            Ok(plaintext) => {
                if let Some(id) = inbox_id {
                    let _ = inbox.mark_inbox_processed(id).await;
                }
                let _ = event_sender
                    .send(Event::MessageReceived {
                        sender: sender_id,
                        plaintext,
                    })
                    .await;
            }
            Err(e) => {
                if let Some(id) = inbox_id {
                    let _ = inbox
                        .mark_inbox_failed(id, &format!("Decryption error: {:?}", e))
                        .await;
                }
            }
        }
    } else if let Some(id) = inbox_id {
        let _ = inbox.mark_inbox_failed(id, "Invalid topic structure").await;
    }
}

impl MqttService {
    /// Initializes the MQTT client and spawns a background worker handling
    /// persistent inbox saving, outbox queue flushing, and reconnection retries.
    pub fn new(
        config: MqttConfig<'_>,
        session_store: Arc<dyn SessionStore>,
        inbox_store: Arc<dyn InboxStore>,
        outbox_store: Arc<dyn OutboxStore>,
        keystore: Arc<dyn KeyStore>,
    ) -> Result<Self, SdkError> {
        let password = generate_mqtt_password(config.user_id, config.signed_pre_key_private)?;

        let mut mqttoptions =
            MqttOptions::new(config.device_id, config.broker_url, config.broker_port);
        mqttoptions.set_credentials(config.user_id, password);
        mqttoptions.set_keep_alive(Duration::from_secs(60));
        mqttoptions.set_clean_session(false);

        if config.use_tls {
            mqttoptions.set_transport(Transport::tls_with_default_config());
        }

        let (client, mut eventloop) = AsyncClient::new(mqttoptions, 50);

        let client_clone = client.clone();
        let uid = config.user_id.to_string();
        let did = config.device_id.to_string();
        let inbox = inbox_store.clone();
        let sessions = session_store.clone();
        let keystore_clone = keystore.clone();
        let spk_priv = *config.signed_pre_key_private;
        let event_sender = config.event_sender;
        let inflight_messages = Arc::new(AtomicUsize::new(0));
        let inflight_clone = inflight_messages.clone();

        tokio::spawn(async move {
            loop {
                match eventloop.poll().await {
                    Ok(MqttEvent::Incoming(Incoming::ConnAck(ack))) => {
                        if !ack.session_present {
                            let topic = format!("/deezchatz/{}/{}/#", uid, did);
                            let _ = client_clone.subscribe(topic, QoS::AtLeastOnce).await;
                        }
                        let _ = event_sender.send(Event::Connected).await;

                        if let Ok(pending_inbox) = inbox.get_pending_inbox().await {
                            for item in pending_inbox {
                                process_message(
                                    &item.topic,
                                    &item.payload,
                                    Some(item.id),
                                    &inbox,
                                    &sessions,
                                    &keystore_clone,
                                    &event_sender,
                                )
                                .await;
                            }
                        }
                    }
                    Ok(MqttEvent::Incoming(Incoming::Publish(p))) => {
                        let inbox_id = inbox.save_to_inbox(&p.topic, &p.payload).await.ok();
                        process_message(
                            &p.topic,
                            &p.payload,
                            inbox_id,
                            &inbox,
                            &sessions,
                            &keystore_clone,
                            &event_sender,
                        )
                        .await;
                    }
                    Err(_) => {
                        let _ = event_sender.send(Event::Disconnected).await;
                        tokio::time::sleep(Duration::from_secs(3)).await;

                        if let Ok(new_password) = generate_mqtt_password(&uid, &spk_priv) {
                            eventloop.mqtt_options.set_credentials(&uid, new_password);
                        }
                    }
                    Ok(MqttEvent::Incoming(Incoming::PubAck(_))) => {
                        let mut current = inflight_clone.load(Ordering::SeqCst);
                        while current > 0 {
                            match inflight_clone.compare_exchange_weak(
                                current,
                                current - 1,
                                Ordering::SeqCst,
                                Ordering::SeqCst,
                            ) {
                                Ok(_) => break,
                                Err(x) => current = x,
                            }
                        }
                    }
                    _ => {}
                }
            }
        });

        Ok(Self {
            client,
            outbox_store,
            inflight_messages,
        })
    }

    /// Publishes a payload and marks it sent in the persistent outbox on success.
    #[instrument(level = "debug", skip_all, err)]
    pub async fn send_payload(
        &self,
        outbox_id: i64,
        topic: &str,
        ciphertext: Vec<u8>,
    ) -> Result<(), SdkError> {
        self.inflight_messages.fetch_add(1, Ordering::SeqCst);
        let res = self
            .client
            .publish(topic, QoS::AtLeastOnce, false, ciphertext)
            .await;
        match res {
            Ok(_) => {
                let _ = self.outbox_store.mark_outbox_sent(outbox_id).await;
                Ok(())
            }
            Err(e) => {
                let mut current = self.inflight_messages.load(Ordering::SeqCst);
                while current > 0 {
                    match self.inflight_messages.compare_exchange_weak(
                        current,
                        current - 1,
                        Ordering::SeqCst,
                        Ordering::SeqCst,
                    ) {
                        Ok(_) => break,
                        Err(x) => current = x,
                    }
                }
                let _ = self
                    .outbox_store
                    .mark_outbox_failed(outbox_id, &e.to_string())
                    .await;
                Err(SdkError::Mqtt(e.to_string()))
            }
        }
    }

    #[instrument(level = "debug", skip_all, err)]
    pub async fn disconnect(&self) -> Result<(), SdkError> {
        let start = tokio::time::Instant::now();
        let timeout = std::time::Duration::from_secs(5);
        while self.inflight_messages.load(Ordering::SeqCst) > 0 {
            if start.elapsed() >= timeout {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        }
        self.client
            .disconnect()
            .await
            .map_err(|e| SdkError::Mqtt(e.to_string()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libsignal_dezire::vxeddsa::gen_keypair;

    #[test]
    fn test_generate_mqtt_password() {
        let keypair = gen_keypair();
        let user_id = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
        let password =
            generate_mqtt_password(user_id, &keypair.secret).expect("failed to generate password");
        assert_eq!(password.len(), 182);

        let sig_b64 = &password[..128];
        let vrf_b64 = &password[128..172];
        let ts_str = &password[172..];

        let ts: u64 = ts_str.parse().expect("timestamp should be an integer");
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        assert!(now.abs_diff(ts) <= 2);

        use base64::{engine::general_purpose::STANDARD, Engine as _};
        use libsignal_dezire::vxeddsa::vxeddsa_verify;

        let sig_bytes = STANDARD.decode(sig_b64).expect("valid sig base64");
        let vrf_bytes = STANDARD.decode(vrf_b64).expect("valid vrf base64");
        let payload = format!("{}{}", user_id, ts_str);

        let mut sig_arr = [0u8; 96];
        sig_arr.copy_from_slice(&sig_bytes);
        let verified_vrf = vxeddsa_verify(&keypair.public, payload.as_bytes(), &sig_arr)
            .expect("signature should verify");
        assert_eq!(verified_vrf.as_slice(), vrf_bytes.as_slice());
    }

    #[test]
    fn test_mqtt_transport_tls() {
        let mut options = MqttOptions::new("test-device", "mqtt.deez.in", 8883);
        options.set_transport(Transport::tls_with_default_config());
        match options.transport() {
            Transport::Tls(_) => {}
            _ => panic!("Expected Transport::Tls"),
        }
    }
}
