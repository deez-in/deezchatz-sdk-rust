use rumqttc::{AsyncClient, MqttOptions, QoS, Event as MqttEvent, Incoming};
use std::time::Duration;
use std::sync::Arc;
use crate::error::SdkError;
use crate::crypto::sign_payload;
use crate::store::{InboxStore, OutboxStore, SessionStore, KeyStore};
use std::time::{SystemTime, UNIX_EPOCH};

/// Real-time events emitted by the SDK
#[derive(Debug, Clone)]
pub enum Event {
    Connected,
    Disconnected,
    MessageReceived {
        sender: String,
        plaintext: Vec<u8>,
    },
}

pub struct MqttService {
    client: AsyncClient,
    outbox_store: Arc<dyn OutboxStore>,
}

async fn decrypt_message(
    payload_bytes: &[u8],
    sender_id: &str,
    sessions: &Arc<dyn SessionStore>,
    keystore: &Arc<dyn KeyStore>,
) -> Result<Vec<u8>, SdkError> {
    use crate::crypto::{EncryptedPayload, ActiveSession, construct_ad, decode_b64_33};
    use libsignal_dezire::x3dh::{x3dh_responder};
    use libsignal_dezire::ratchet::{init_receiver_state, decrypt as ratchet_decrypt};
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    let enc_payload: EncryptedPayload = serde_json::from_slice(payload_bytes)
        .map_err(|e| SdkError::Crypto(format!("Invalid payload json: {}", e)))?;

    let existing_session_bytes = sessions.get_session(sender_id).await?;
    
    let mut active_session: ActiveSession;

    if let Some(bytes) = existing_session_bytes {
        active_session = serde_json::from_slice(&bytes)
            .map_err(|e| SdkError::Storage(format!("Session deserialize error: {}", e)))?;
    } else {
        // Must be an initial message
        let ik_b64 = enc_payload.identity_key.as_ref().ok_or_else(|| SdkError::Crypto("Missing identityKey for new session".into()))?;
        let ek_b64 = enc_payload.ephemeral_key.as_ref().ok_or_else(|| SdkError::Crypto("Missing ephemeralKey for new session".into()))?;
        
        let sender_identity_pub = decode_b64_33(ik_b64)?;
        let sender_ephemeral_pub = decode_b64_33(ek_b64)?;
        let spk_id = enc_payload.spk_id.unwrap_or(1);
        let opk_id = enc_payload.opk_id;

        let local_id_key = keystore.get_identity_key().await?.ok_or_else(|| SdkError::Storage("Identity key missing".into()))?;
        let local_spk = keystore.get_signed_pre_key(spk_id).await?.ok_or_else(|| SdkError::Storage("SPK missing".into()))?;
        
        let opk_private = if let Some(oid) = opk_id {
            if let Some(k) = keystore.consume_one_time_pre_key(oid).await? {
                Some(k.0)
            } else {
                None
            }
        } else {
            None
        };

        let shared_secret = x3dh_responder(
            &local_id_key.0,
            &local_spk.0,
            opk_private.as_ref(),
            &sender_identity_pub,
            &sender_ephemeral_pub,
        ).map_err(|e| SdkError::Crypto(format!("X3DH responder failed: {:?}", e)))?;

        let ratchet_state = init_receiver_state(shared_secret, (local_spk.0, local_spk.1));

        active_session = ActiveSession {
            ratchet_state,
            remote_identity_pub: sender_identity_pub,
            remote_user_id: sender_id.to_string(),
            remote_device_id: String::new(), // Not critical for receiving, just sending
        };
    }

    let local_id_key = keystore.get_identity_key().await?.ok_or_else(|| SdkError::Storage("Identity key missing".into()))?;
    let ad = construct_ad(&active_session.remote_identity_pub, &local_id_key.1);

    let header_bytes = STANDARD.decode(&enc_payload.header)
        .map_err(|e| SdkError::Crypto(format!("Invalid header base64: {}", e)))?;
    let ciphertext_bytes = STANDARD.decode(&enc_payload.ciphertext)
        .map_err(|e| SdkError::Crypto(format!("Invalid ciphertext base64: {}", e)))?;

    let plaintext = ratchet_decrypt(&mut active_session.ratchet_state, &header_bytes, &ciphertext_bytes, &ad)
        .map_err(|e| SdkError::Crypto(format!("Ratchet decrypt failed: {:?}", e)))?;

    let session_bytes = serde_json::to_vec(&active_session)
        .map_err(|e| SdkError::Storage(format!("Session serialize error: {}", e)))?;
    sessions.save_session(sender_id, &session_bytes).await?;

    Ok(plaintext)
}

impl MqttService {
    /// Initializes the MQTT client and spawns a background worker handling
    /// persistent inbox saving, outbox queue flushing, and reconnection retries.
    pub fn new(
        broker_url: &str,
        broker_port: u16,
        user_id: &str,
        device_id: &str,
        identity_private: &[u8; 32],
        event_sender: tokio::sync::mpsc::Sender<Event>,
        session_store: Arc<dyn SessionStore>,
        inbox_store: Arc<dyn InboxStore>,
        outbox_store: Arc<dyn OutboxStore>,
        keystore: Arc<dyn KeyStore>,
    ) -> Result<Self, SdkError> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| SdkError::Mqtt(e.to_string()))?
            .as_secs()
            .to_string();

        let payload = format!("{}{}", user_id, ts);
        let (sig, vrf) = sign_payload(identity_private, payload.as_bytes())?;
        
        let password = format!("{}{}{}", sig, vrf, ts);

        let mut mqttoptions = MqttOptions::new(device_id, broker_url, broker_port);
        mqttoptions.set_credentials(user_id, password);
        mqttoptions.set_keep_alive(Duration::from_secs(60));
        mqttoptions.set_clean_session(false);

        let (client, mut eventloop) = AsyncClient::new(mqttoptions, 50);
        
        let client_clone = client.clone();
        let uid = user_id.to_string();
        let did = device_id.to_string();
        let inbox = inbox_store.clone();
        let outbox = outbox_store.clone();
        let sessions = session_store.clone();
        let keystore_clone = keystore.clone();

        tokio::spawn(async move {
            loop {
                match eventloop.poll().await {
                    Ok(MqttEvent::Incoming(Incoming::ConnAck(_))) => {
                        let topic = format!("/deezchatz/{}/{}/#", uid, did);
                        let _ = client_clone.subscribe(topic, QoS::AtLeastOnce).await;
                        let _ = event_sender.send(Event::Connected).await;

                        if let Ok(pending_outbox) = outbox.get_pending_outbox().await {
                            for item in pending_outbox {
                                match client_clone
                                    .publish(item.topic.clone(), QoS::AtLeastOnce, false, item.payload.clone())
                                    .await
                                {
                                    Ok(_) => {
                                        let _ = outbox.mark_outbox_sent(item.id).await;
                                    }
                                    Err(e) => {
                                        let _ = outbox.mark_outbox_failed(item.id, &e.to_string()).await;
                                    }
                                }
                            }
                        }

                        if let Ok(pending_inbox) = inbox.get_pending_inbox().await {
                            for item in pending_inbox {
                                let parts: Vec<&str> = item.topic.split('/').collect();
                                if parts.len() >= 6 {
                                    let sender_id = parts[4].to_string();
                                    
                                    match decrypt_message(&item.payload, &sender_id, &sessions, &keystore_clone).await {
                                        Ok(plaintext) => {
                                            let _ = inbox.mark_inbox_processed(item.id).await;
                                            let _ = event_sender.send(Event::MessageReceived {
                                                sender: sender_id,
                                                plaintext,
                                            }).await;
                                        }
                                        Err(e) => {
                                            let _ = inbox.mark_inbox_failed(item.id, &format!("Decryption error: {:?}", e)).await;
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Ok(MqttEvent::Incoming(Incoming::Publish(p))) => {
                        let inbox_id = inbox.save_to_inbox(&p.topic, &p.payload).await.ok();

                        let parts: Vec<&str> = p.topic.split('/').collect();
                        if parts.len() >= 6 {
                            let sender_id = parts[4].to_string();
                            
                            match decrypt_message(&p.payload, &sender_id, &sessions, &keystore_clone).await {
                                Ok(plaintext) => {
                                    if let Some(id) = inbox_id {
                                        let _ = inbox.mark_inbox_processed(id).await;
                                    }
                                    let _ = event_sender.send(Event::MessageReceived {
                                        sender: sender_id,
                                        plaintext,
                                    }).await;
                                }
                                Err(e) => {
                                    if let Some(id) = inbox_id {
                                        let _ = inbox.mark_inbox_failed(id, &format!("Decryption error: {:?}", e)).await;
                                    }
                                }
                            }
                        } else if let Some(id) = inbox_id {
                            let _ = inbox.mark_inbox_failed(id, "Invalid topic structure").await;
                        }
                    }
                    Err(_) => {
                        let _ = event_sender.send(Event::Disconnected).await;
                        tokio::time::sleep(Duration::from_secs(3)).await;
                    }
                    _ => {}
                }
            }
        });

        Ok(Self {
            client,
            outbox_store,
        })
    }

    /// Publishes a payload and marks it sent in the persistent outbox on success.
    pub async fn send_payload(&self, outbox_id: i64, topic: &str, ciphertext: Vec<u8>) -> Result<(), SdkError> {
        let res = self.client.publish(topic, QoS::AtLeastOnce, false, ciphertext).await;
        match res {
            Ok(_) => {
                let _ = self.outbox_store.mark_outbox_sent(outbox_id).await;
                Ok(())
            }
            Err(e) => {
                let _ = self.outbox_store.mark_outbox_failed(outbox_id, &e.to_string()).await;
                Err(SdkError::Mqtt(e.to_string()))
            }
        }
    }
}

