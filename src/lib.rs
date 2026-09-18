//! # DeezChatz SDK for Rust
//!
//! An asynchronous Rust SDK for the DeezChatz platform, providing end-to-end encryption
//! via the Signal Protocol (X3DH and Double Ratchet), zero-trust REST authentication via
//! VXEdDSA signatures and VRF proofs, and real-time messaging over MQTT.
//!
//! ## Core Architecture
//!
//! - **End-to-End Cryptography**: Deeply integrated with `libsignal-dezire` to manage Identity
//!   Keys, Signed Pre-Keys, One-Time Pre-Keys (OPKs), and active Double Ratchet sessions.
//! - **Zero-Trust Stateless Authentication**: Authenticates every REST request using cryptographic
//!   VXEdDSA signatures (`X-User-Id`, `X-Timestamp`, `X-Signature`, `X-Vrf`).
//! - **Real-Time MQTT Transport**: Connects to the DeezChatz MQTT broker with cryptographic password
//!   tokens, receiving events via an asynchronous `tokio::sync::mpsc::Receiver`.
//! - **Bring-Your-Own-Storage (BYOS)**: Abstract async traits for key persistence ([`KeyStore`]),
//!   session state ([`SessionStore`]), incoming message queue ([`InboxStore`]), and outgoing
//!   queue ([`OutboxStore`]).
//! - **Guaranteed Delivery & Crash Resilience**: Unprocessed inbound messages and pending outbound
//!   messages are safely persisted to disk to prevent data loss across crashes or network disruptions.
//! - **Multi-Type Framed Payloads**: Native support for UTF-8 text, Opus voice notes, and JPEG image
//!   transfers with captions and timestamps.
//!
//! ## Quick Start
//!
//! ```no_run
//! use std::sync::Arc;
//! use deezchatz_sdk::{DeezChatzClient, ClientConfig, Event, decode_payload, DecodedPayload};
//! # use deezchatz_sdk::{KeyStore, SessionStore, InboxStore, OutboxStore, SdkError};
//! # use async_trait::async_trait;
//! # struct DummyStore;
//! # #[async_trait] impl KeyStore for DummyStore {
//! #     async fn save_identity_key(&self, _: &[u8; 32], _: &[u8; 33]) -> Result<(), SdkError> { Ok(()) }
//! #     async fn get_identity_key(&self) -> Result<Option<([u8; 32], [u8; 33])>, SdkError> { Ok(None) }
//! #     async fn save_signed_pre_key(&self, _: u32, _: &[u8; 32], _: &[u8; 33]) -> Result<(), SdkError> { Ok(()) }
//! #     async fn get_signed_pre_key(&self, _: u32) -> Result<Option<([u8; 32], [u8; 33])>, SdkError> { Ok(None) }
//! #     async fn save_one_time_pre_keys(&self, _: Vec<(u32, [u8; 32], [u8; 33])>) -> Result<(), SdkError> { Ok(()) }
//! #     async fn consume_one_time_pre_key(&self, _: u32) -> Result<Option<([u8; 32], [u8; 33])>, SdkError> { Ok(None) }
//! # }
//! # #[async_trait] impl SessionStore for DummyStore {
//! #     async fn save_session(&self, _: &str, _: &[u8]) -> Result<(), SdkError> { Ok(()) }
//! #     async fn get_session(&self, _: &str) -> Result<Option<Vec<u8>>, SdkError> { Ok(None) }
//! #     async fn delete_session(&self, _: &str) -> Result<(), SdkError> { Ok(()) }
//! # }
//! # #[async_trait] impl InboxStore for DummyStore {
//! #     async fn save_to_inbox(&self, _: &str, _: &[u8]) -> Result<i64, SdkError> { Ok(1) }
//! #     async fn mark_inbox_processed(&self, _: i64) -> Result<(), SdkError> { Ok(()) }
//! #     async fn mark_inbox_failed(&self, _: i64, _: &str) -> Result<(), SdkError> { Ok(()) }
//! #     async fn get_pending_inbox(&self) -> Result<Vec<deezchatz_sdk::InboxEntry>, SdkError> { Ok(vec![]) }
//! # }
//! # #[async_trait] impl OutboxStore for DummyStore {
//! #     async fn save_to_outbox(&self, _: &str, _: &str, _: &str, _: &[u8]) -> Result<i64, SdkError> { Ok(1) }
//! #     async fn mark_outbox_sent(&self, _: i64) -> Result<(), SdkError> { Ok(()) }
//! #     async fn mark_outbox_failed(&self, _: i64, _: &str) -> Result<(), SdkError> { Ok(()) }
//! #     async fn get_pending_outbox(&self) -> Result<Vec<deezchatz_sdk::OutboxEntry>, SdkError> { Ok(vec![]) }
//! # }
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let config = ClientConfig::production();
//!     let store = Arc::new(DummyStore);
//!
//!     let mut client = DeezChatzClient::new(
//!         config,
//!         store.clone(),
//!         store.clone(),
//!         store.clone(),
//!         store.clone(),
//!     );
//!
//!     // Connect to the real-time MQTT broker
//!     let mut event_rx = client.connect("my-user-id", "my-device-id").await?;
//!
//!     // Process incoming messages
//!     tokio::spawn(async move {
//!         while let Some(event) = event_rx.recv().await {
//!             if let Event::MessageReceived { sender, plaintext } = event {
//!                 if let Ok(payload) = decode_payload(&plaintext) {
//!                     match payload {
//!                         DecodedPayload::Text { text } => println!("{}: {}", sender, text),
//!                         DecodedPayload::Voice { audio_bytes } => println!("Voice note ({} bytes)", audio_bytes.len()),
//!                         DecodedPayload::Image { caption, image_bytes, .. } => println!("Image '{}' ({} bytes)", caption, image_bytes.len()),
//!                     }
//!                 }
//!             }
//!         }
//!     });
//!
//!     // Send an encrypted text message
//!     let sent = client.send_text_message("recipient-id", "Hello!").await?;
//!     println!("Message sent with ID: {}", sent.message_id);
//!
//!     client.disconnect().await?;
//!     Ok(())
//! }
//! ```

pub mod client;
pub mod crypto;
pub mod error;
pub mod messaging;
pub mod oauth;
pub mod transport;

pub use client::{ClientConfig, DeezChatzClient, SentMessage};
pub use error::SdkError;
pub use messaging::{
    decode_payload, encode_image_payload, encode_text_payload, encode_voice_payload,
    DecodedPayload, InboxEntry, InboxStore, KeyStore, MessageStatus, OutboxEntry, OutboxStore,
    PayloadError, SessionStore, PAYLOAD_TYPE_IMAGE, PAYLOAD_TYPE_TEXT, PAYLOAD_TYPE_VOICE,
};
pub use transport::Event;
pub use transport::SyncBundleResponse;

pub use base64;
pub use libsignal_dezire;
