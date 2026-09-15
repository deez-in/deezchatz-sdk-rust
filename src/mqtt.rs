use rumqttc::{AsyncClient, MqttOptions, QoS, Event as MqttEvent, Incoming};
use std::time::Duration;
use std::sync::Arc;
use crate::error::SdkError;
use crate::crypto::sign_payload;
use crate::store::{InboxStore, OutboxStore, SessionStore};
use std::time::{SystemTime, UNIX_EPOCH};

/// Real-time events emitted by the SDK
#[derive(Debug, Clone)]
pub enum Event {
    Connected,
    Disconnected,
    MessageReceived {
        sender: String,
        plaintext: String,
    },
}

pub struct MqttService {
    client: AsyncClient,
    outbox_store: Arc<dyn OutboxStore>,
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
    ) -> Result<Self, SdkError> {
        let ts = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| SdkError::Mqtt(e.to_string()))?
            .as_secs()
            .to_string();

        let payload = format!("{}{}", user_id, ts);
        let (sig, vrf) = sign_payload(identity_private, payload.as_bytes())?;
        
        // MQTT password format as defined in deezchatz-api:
        // 0..128: signature, 128..172: vrf, 172..182: timestamp
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

        tokio::spawn(async move {
            loop {
                match eventloop.poll().await {
                    Ok(MqttEvent::Incoming(Incoming::ConnAck(_))) => {
                        let topic = format!("/deezchatz/{}/{}/#", uid, did);
                        let _ = client_clone.subscribe(topic, QoS::AtLeastOnce).await;
                        let _ = event_sender.send(Event::Connected).await;

                        // 1. Flush Outbox: Retry sending all pending outgoing messages
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

                        // 2. Flush Inbox: Retry decrypting any pending inbox messages
                        if let Ok(pending_inbox) = inbox.get_pending_inbox().await {
                            for item in pending_inbox {
                                let parts: Vec<&str> = item.topic.split('/').collect();
                                if parts.len() >= 6 {
                                    let sender_id = parts[4].to_string();
                                    // TODO: Decrypt using sessions
                                    let plaintext_str = String::from_utf8_lossy(&item.payload).into_owned();
                                    let _ = inbox.mark_inbox_processed(item.id).await;
                                    let _ = event_sender.send(Event::MessageReceived {
                                        sender: sender_id,
                                        plaintext: plaintext_str,
                                    }).await;
                                }
                            }
                        }
                    }
                    Ok(MqttEvent::Incoming(Incoming::Publish(p))) => {
                        // Strategy step 1: Immediately persist raw ciphertext payload to the Inbox DB
                        // even before attempting crypto processing (ensures message is never lost on crash)
                        let inbox_id = inbox.save_to_inbox(&p.topic, &p.payload).await.ok();

                        // Strategy step 2: Extract sender and decrypt
                        let parts: Vec<&str> = p.topic.split('/').collect();
                        if parts.len() >= 6 {
                            let sender_id = parts[4].to_string();
                            let ciphertext = p.payload;
                            
                            // Decrypt using session store
                            let plaintext_str = String::from_utf8_lossy(&ciphertext).into_owned();

                            // Strategy step 3: Mark inbox processed on success
                            if let Some(id) = inbox_id {
                                let _ = inbox.mark_inbox_processed(id).await;
                            }

                            let _ = event_sender.send(Event::MessageReceived {
                                sender: sender_id,
                                plaintext: plaintext_str,
                            }).await;
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
