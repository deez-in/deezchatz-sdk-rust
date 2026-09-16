use rumqttc::{AsyncClient, MqttOptions, QoS, Event as MqttEvent, Incoming, Transport};
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

        use libsignal_dezire::utils::decode_public_key;
        use libsignal_dezire::ratchet::{DhPublicKey, DhPrivateKey};

        let spk_priv = DhPrivateKey::from(local_spk.0);
        let spk_pub_bytes = decode_public_key(&local_spk.1).map_err(|_| SdkError::Crypto("Invalid SPK pub".into()))?;
        let spk_pub = DhPublicKey::from(spk_pub_bytes);

        let ratchet_state = init_receiver_state(shared_secret, (spk_priv, spk_pub));

        active_session = ActiveSession {
            ratchet_state,
            remote_identity_pub: sender_identity_pub.to_vec(),
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

impl MqttService {
    /// Initializes the MQTT client and spawns a background worker handling
    /// persistent inbox saving, outbox queue flushing, and reconnection retries.
    pub fn new(
        broker_url: &str,
        broker_port: u16,
        use_tls: bool,
        user_id: &str,
        device_id: &str,
        signed_pre_key_private: &[u8; 32],
        event_sender: tokio::sync::mpsc::Sender<Event>,
        session_store: Arc<dyn SessionStore>,
        inbox_store: Arc<dyn InboxStore>,
        outbox_store: Arc<dyn OutboxStore>,
        keystore: Arc<dyn KeyStore>,
    ) -> Result<Self, SdkError> {
        let password = generate_mqtt_password(user_id, signed_pre_key_private)?;

        let mut mqttoptions = MqttOptions::new(device_id, broker_url, broker_port);
        mqttoptions.set_credentials(user_id, password);
        mqttoptions.set_keep_alive(Duration::from_secs(60));
        mqttoptions.set_clean_session(false);

        if use_tls {
            mqttoptions.set_transport(Transport::tls_with_default_config());
        }

        let (client, mut eventloop) = AsyncClient::new(mqttoptions, 50);
        
        let client_clone = client.clone();
        let uid = user_id.to_string();
        let did = device_id.to_string();
        let inbox = inbox_store.clone();
        let sessions = session_store.clone();
        let keystore_clone = keystore.clone();
        let spk_priv = *signed_pre_key_private;

        tokio::spawn(async move {
            loop {
                match eventloop.poll().await {
                    Ok(MqttEvent::Incoming(Incoming::ConnAck(_))) => {
                        let topic = format!("/deezchatz/{}/{}/#", uid, did);
                        let _ = client_clone.subscribe(topic, QoS::AtLeastOnce).await;
                        let _ = event_sender.send(Event::Connected).await;

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

                        // Refresh credentials with a fresh timestamp and signature before reconnecting
                        if let Ok(new_password) = generate_mqtt_password(&uid, &spk_priv) {
                            eventloop.mqtt_options.set_credentials(&uid, new_password);
                        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use libsignal_dezire::vxeddsa::gen_keypair;

    #[test]
    fn test_generate_mqtt_password() {
        let keypair = gen_keypair();
        let user_id = "f47ac10b-58cc-4372-a567-0e02b2c3d479";
        let password = generate_mqtt_password(user_id, &keypair.secret).expect("failed to generate password");
        // 128 (signature base64) + 44 (vrf base64) + 10 (unix timestamp) = 182 characters
        assert_eq!(password.len(), 182);

        let sig_b64 = &password[..128];
        let vrf_b64 = &password[128..172];
        let ts_str = &password[172..];

        let ts: u64 = ts_str.parse().expect("timestamp should be an integer");
        let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
        assert!(now.abs_diff(ts) <= 2);

        // Verify that signature is valid with the public key
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        use libsignal_dezire::vxeddsa::vxeddsa_verify;

        let sig_bytes = STANDARD.decode(sig_b64).expect("valid sig base64");
        let vrf_bytes = STANDARD.decode(vrf_b64).expect("valid vrf base64");
        let payload = format!("{}{}", user_id, ts_str);

        let mut sig_arr = [0u8; 96];
        sig_arr.copy_from_slice(&sig_bytes);
        let verified_vrf = vxeddsa_verify(&keypair.public, payload.as_bytes(), &sig_arr).expect("signature should verify");
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


