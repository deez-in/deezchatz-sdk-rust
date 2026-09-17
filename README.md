# DeezChatz SDK Rust 🦀

[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-orange.svg)](https://www.gnu.org/licenses/agpl-3.0)

The **deezchatz-sdk-rust** is a high-performance, asynchronous Rust client for the DeezChatz ecosystem. It abstracts the complexities of the Signal Protocol (X3DH, Double Ratchet), zero-trust VXEdDSA REST authentication, and real-time MQTT networking into an intuitive, developer-friendly interface.

This SDK is engineered for developers building CLI clients, automated bots, desktop apps, or backend services interfacing securely with DeezChatz.

---

## Features

- **Automated End-to-End Cryptography**: Deeply integrated with `libsignal-dezire` to manage Curve25519 Identity Keys, Signed Pre-Keys, One-Time Pre-Keys (OPKs), and active Double Ratchet ratchet states.
- **Zero-Trust Stateless REST Authentication**: Signs every API request using VXEdDSA signatures and VRF proofs (`X-User-Id`, `X-Timestamp`, `X-Signature`, `X-Vrf`), eliminating cookies and JWT vulnerabilities.
- **Dynamic MQTT Authentication**: Generates time-bounded cryptographic signatures for broker passwords, automatically refreshing credentials during reconnection loops.
- **Event-Driven MQTT Transport**: Asynchronous `tokio::sync::mpsc::Receiver` for real-time events (`Connected`, `Disconnected`, `MessageReceived`).
- **Bring-Your-Own-Storage (BYOS)**: Decoupled storage model via async traits: [`KeyStore`], [`SessionStore`], [`InboxStore`], and [`OutboxStore`].
- **Crash Resilience & Delivery Guarantees**:
  - Raw incoming ciphertexts are saved to [`InboxStore`] immediately upon MQTT packet arrival before decryption.
  - Outgoing messages are enqueued to [`OutboxStore`] as pending, tracked in-flight, and marked sent only when `PUBACK` is confirmed.
  - Graceful disconnection drains pending in-flight messages before closing sockets.
- **Rich Media Payload Framing**: Native encoding and decoding for UTF-8 text, Opus voice notes, and JPEG image transfers with captions and timestamps.

---

## Installation

Add `deezchatz-sdk-rust` to your `Cargo.toml`:

```toml
[dependencies]
deezchatz-sdk-rust = { path = "../deezchatz-sdk-rust" } # or git repository
tokio = { version = "1", features = ["full"] }
async-trait = "0.1"
```

---

## Architecture Overview

```
                      +-----------------------------+
                      |       DeezChatz Client      |
                      +--------------+--------------+
                                     |
               +---------------------+---------------------+
               |                                           |
               v                                           v
     +-------------------+                       +-------------------+
     |  REST API Client  |                       |  MQTT Transport   |
     | (Stateless VXEdDSA|                       | (Rumqttc + TLS /  |
     |    Signatures)    |                       | Dynamic Passwords)|
     +---------+---------+                       +---------+---------+
               |                                           |
               | POST /register/device                     | /deezchatz/{uid}/{did}/#
               | POST /bundle/{identifier}                 | Inbound / Outbound
               v                                           v
    +---------------------+                     +---------------------+
    |  DeezChatz REST API |                     | DeezChatz Broker    |
    +---------------------+                     +---------------------+
```

### Protocol Flow
1. **Registration**: The client creates Identity Keys, a Signed Pre-Key, a Signed Device Key, and a pool of One-Time Pre-Keys (OPKs). These are cryptographically signed and uploaded to the server via OAuth 2.0 PKCE.
2. **Session Initiation (X3DH)**: When sending a message to a new contact, the SDK requests their pre-key bundle (`POST /bundle/{id}`), performs X3DH key agreement, initializes the Double Ratchet sender state, and attaches the ephemeral key to the first ciphertext.
3. **Double Ratchet**: Subsequent messages advance the sending and receiving ratchets, deriving ephemeral symmetric keys per message for forward and backward secrecy.
4. **Transport**: Ciphertexts are transmitted over MQTT topic `/deezchatz/{recipient_user_id}/{recipient_device_id}/{sender_user_id}/{sender_device_id}`.

---

## Quick Start

### 1. Implement Storage Backend (BYOS)

Implement the four storage traits using your preferred backend (e.g. SQLite, SQLCipher, Sled, Redis):

```rust
use async_trait::async_trait;
use deezchatz_sdk_rust::{
    KeyStore, SessionStore, InboxStore, OutboxStore,
    InboxEntry, OutboxEntry, SdkError,
};

pub struct MyStorage {
    // Database connection pool (e.g. sqlx::SqlitePool)
}

#[async_trait]
impl KeyStore for MyStorage {
    async fn save_identity_key(&self, priv_key: &[u8; 32], pub_key: &[u8; 33]) -> Result<(), SdkError> {
        // Persist local Curve25519 identity key
        Ok(())
    }

    async fn get_identity_key(&self) -> Result<Option<([u8; 32], [u8; 33])>, SdkError> {
        // Return local identity key pair
        Ok(None)
    }

    async fn save_signed_pre_key(&self, id: u32, priv_key: &[u8; 32], pub_key: &[u8; 33]) -> Result<(), SdkError> {
        // Persist signed pre-key
        Ok(())
    }

    async fn get_signed_pre_key(&self, id: u32) -> Result<Option<([u8; 32], [u8; 33])>, SdkError> {
        // Return signed pre-key
        Ok(None)
    }

    async fn save_one_time_pre_keys(&self, keys: Vec<(u32, [u8; 32], [u8; 33])>) -> Result<(), SdkError> {
        // Persist batch of generated OPKs
        Ok(())
    }

    async fn consume_one_time_pre_key(&self, id: u32) -> Result<Option<([u8; 32], [u8; 33])>, SdkError> {
        // Atomically fetch and delete an OPK by ID
        Ok(None)
    }
}

#[async_trait]
impl SessionStore for MyStorage {
    async fn save_session(&self, recipient_id: &str, session_data: &[u8]) -> Result<(), SdkError> {
        // Upsert Double Ratchet session state bytes
        Ok(())
    }

    async fn get_session(&self, recipient_id: &str) -> Result<Option<Vec<u8>>, SdkError> {
        // Retrieve Double Ratchet session state
        Ok(None)
    }

    async fn delete_session(&self, recipient_id: &str) -> Result<(), SdkError> {
        // Delete session upon reset
        Ok(())
    }
}

#[async_trait]
impl InboxStore for MyStorage {
    async fn save_to_inbox(&self, topic: &str, payload: &[u8]) -> Result<i64, SdkError> {
        // Save raw MQTT incoming payload immediately on receipt
        Ok(1)
    }

    async fn mark_inbox_processed(&self, id: i64) -> Result<(), SdkError> {
        // Mark message successfully decrypted and dispatched
        Ok(())
    }

    async fn mark_inbox_failed(&self, id: i64, error: &str) -> Result<(), SdkError> {
        // Record decryption failure
        Ok(())
    }

    async fn get_pending_inbox(&self) -> Result<Vec<InboxEntry>, SdkError> {
        // Return unhandled incoming messages for replay on reconnect
        Ok(vec![])
    }
}

#[async_trait]
impl OutboxStore for MyStorage {
    async fn save_to_outbox(
        &self,
        recipient_id: &str,
        message_id: &str,
        topic: &str,
        payload: &[u8],
    ) -> Result<i64, SdkError> {
        // Enqueue outbound message before transmission
        Ok(1)
    }

    async fn mark_outbox_sent(&self, id: i64) -> Result<(), SdkError> {
        // Confirm message transmission on PUBACK
        Ok(())
    }

    async fn mark_outbox_failed(&self, id: i64, error: &str) -> Result<(), SdkError> {
        // Record outbound failure
        Ok(())
    }

    async fn get_pending_outbox(&self) -> Result<Vec<OutboxEntry>, SdkError> {
        // Return unsent messages for retry
        Ok(vec![])
    }
}
```

---

### 2. Client Initialization & Configuration

```rust
use std::sync::Arc;
use deezchatz_sdk_rust::{DeezChatzClient, ClientConfig};

// Pre-configured environments:
let config = ClientConfig::production();   // https://api.chatz.deez.in, mqtt.deez.in:8883 (TLS)
// let config = ClientConfig::development(); // http://localhost:3000, localhost:1883
// let config = ClientConfig::from_env();    // Configured via DEEZCHATZ_* environment variables

let storage = Arc::new(MyStorage::new());

let mut client = DeezChatzClient::new(
    config,
    storage.clone(), // KeyStore
    storage.clone(), // SessionStore
    storage.clone(), // InboxStore
    storage.clone(), // OutboxStore
);
```

#### Environment Variables (`ClientConfig::from_env()`)

| Variable | Default | Description |
|---|---|---|
| `DEEZCHATZ_API_URL` | `https://api.chatz.deez.in` | REST API base URL |
| `DEEZCHATZ_MQTT_URL` | `mqtt.deez.in` | MQTT broker hostname |
| `DEEZCHATZ_MQTT_PORT` | `8883` | MQTT broker port |
| `DEEZCHATZ_OPK_COUNT` | `100` | Number of One-Time Pre-Keys generated |
| `DEEZCHATZ_USE_TLS` | `true` (if port 8883) | Whether to use TLS encryption |

---

### 3. Device Registration (OAuth 2.0 PKCE)

Device registration uses Google OAuth 2.0 with PKCE:

```rust
use deezchatz_sdk_rust::oauth;

// 1. Generate code verifier and challenge
let verifier = oauth::generate_code_verifier();
let challenge = oauth::generate_code_challenge(&verifier);

// 2. Build Google OAuth authorization URL
let auth_url = oauth::build_google_auth_url(
    "YOUR_GOOGLE_CLIENT_ID",
    "http://localhost:8080/callback",
    &challenge,
    &["openid", "email", "profile"],
);
println!("Open in browser: {}", auth_url);

// 3. Complete registration using returned auth code
let auth_code = "4/0AeaYSH...";
client.register_with_pkce(
    auth_code,
    Some(&verifier),
    "http://localhost:8080/callback",
    "+1234567890",
).await?;

println!("Registered User ID: {}", client.user_id().unwrap());
println!("Device ID: {}", client.device_id().unwrap());
```

---

### 4. Real-Time Messaging & Event Loop

```rust
use deezchatz_sdk_rust::{Event, decode_payload, DecodedPayload};

// Connect to MQTT broker
let mut event_rx = client.connect("my-user-id", "my-device-id").await?;

// Spawn real-time event processing loop
tokio::spawn(async move {
    while let Some(event) = event_rx.recv().await {
        match event {
            Event::Connected => {
                println!("Connected to DeezChatz MQTT broker");
            }
            Event::Disconnected => {
                println!("Disconnected from broker (reconnecting...)");
            }
            Event::MessageReceived { sender, plaintext } => {
                match decode_payload(&plaintext) {
                    Ok(DecodedPayload::Text { text }) => {
                        println!("💬 [Text] {}: {}", sender, text);
                    }
                    Ok(DecodedPayload::Voice { audio_bytes }) => {
                        println!("🎤 [Voice] {} sent {} bytes of audio", sender, audio_bytes.len());
                    }
                    Ok(DecodedPayload::Image { timestamp, caption, image_bytes }) => {
                        println!("🖼️ [Image] {} sent image ({} bytes) with caption '{}'", sender, image_bytes.len(), caption);
                    }
                    Err(e) => {
                        eprintln!("Failed to decode framed payload: {:?}", e);
                    }
                }
            }
        }
    }
});
```

---

### 5. Sending Messages

The SDK handles X3DH pre-key bundle fetching and ratchet establishment automatically on the first message sent to any recipient.

#### Sending Text Messages
```rust
let sent = client.send_text_message("recipient@example.com", "Hello from Rust!").await?;
println!("Message ID: {}, Recipient User ID: {}", sent.message_id, sent.recipient_user_id);
```

#### Sending Voice Notes
```rust
let opus_audio_bytes = std::fs::read("audio_note.opus")?;
let sent = client.send_voice_message("recipient@example.com", &opus_audio_bytes).await?;
```

#### Sending Images with Captions
```rust
let jpeg_bytes = std::fs::read("photo.jpg")?;
// Sends image with current timestamp and caption
let sent = client.send_image_message("recipient@example.com", &jpeg_bytes, Some("Sunset at the beach 🌅")).await?;

// Or specify explicit UNIX timestamp
let sent = client.send_image_message_with_timestamp("recipient@example.com", &jpeg_bytes, Some("Sunset"), 1726030464).await?;
```

#### Sending DecodedPayload Directly
```rust
use deezchatz_sdk_rust::DecodedPayload;

let payload = DecodedPayload::Text { text: "Reusable payload".into() };
client.send_payload("recipient@example.com", &payload).await?;
```

---

### 6. Contact Sync & Profile Inspection

To query a contact's profile without consuming a One-Time Pre-Key (OPK):

```rust
let profile = client.get_sync_bundle("target-user-id").await?;
println!("Name: {:?}", profile.display_name);
println!("Picture URL: {:?}", profile.picture);
println!("Identity Key: {}", profile.identity_key);
```

---

### 7. Graceful Disconnection

```rust
// Waits up to 5 seconds for in-flight messages to receive PUBACK before disconnecting
client.disconnect().await?;
```

---

## Payload Framing Specification

DeezChatz uses structured binary payload framing compatible with mobile and web clients:

| Type Byte | Message Type | Wire Layout |
|:---:|:---|:---|
| `0x00` | Text | `[0x00, ...utf8_bytes]` |
| `0x01` | Voice | `[0x01, ...opus_audio_bytes]` |
| `0x02` | Image | `[0x02, timestamp (4 bytes BE), caption_len (2 bytes BE), caption (...utf8_bytes), ...jpeg_bytes]` |

### Decoding & Encoding Utilities

```rust
use deezchatz_sdk_rust::{
    decode_payload, encode_text_payload, encode_voice_payload, encode_image_payload,
    DecodedPayload,
};

// Encoding
let text_bytes = encode_text_payload("Hello!");
let voice_bytes = encode_voice_payload(&[0x4f, 0x67, 0x67, 0x53]);
let image_bytes = encode_image_payload(1726030464, "Caption", &[0xff, 0xd8, 0xff]);

// Decoding
let payload = decode_payload(&text_bytes)?;
assert_eq!(payload, DecodedPayload::Text { text: "Hello!".to_string() });
```

---

## API Method Reference

### `DeezChatzClient`

| Method | Endpoint / Layer | Description |
|---|---|---|
| `new(config, keystore, sessionstore, inboxstore, outboxstore)` | Client Constructor | Instantiates a client with BYOS persistence |
| `register_with_pkce(code, verifier, redirect_uri, phone)` | `POST /register/google/pkce`<br/>`POST /register/device` | Complete registration via OAuth 2.0 PKCE auth code & uploads signed keys |
| `connect(user_id, device_id)` | MQTT Broker (`/deezchatz/...`) | Connects to MQTT broker using signature-auth password; returns event receiver |
| `send_text_message(recipient, text)` | X3DH / Double Ratchet + MQTT | Encodes text (`0x00`) and sends end-to-end encrypted message |
| `send_voice_message(recipient, audio)` | X3DH / Double Ratchet + MQTT | Encodes voice (`0x01`) and sends end-to-end encrypted message |
| `send_image_message(recipient, image, caption)` | X3DH / Double Ratchet + MQTT | Encodes image (`0x02`) with current timestamp and optional caption |
| `send_image_message_with_timestamp(recipient, image, caption, ts)` | X3DH / Double Ratchet + MQTT | Encodes image (`0x02`) with custom timestamp and caption |
| `send_payload(recipient, &DecodedPayload)` | X3DH / Double Ratchet + MQTT | Encodes a `DecodedPayload` enum and sends encrypted |
| `send_message(recipient, payload_bytes)` | X3DH / Double Ratchet + MQTT | Sends raw binary payload end-to-end encrypted |
| `get_sync_bundle(target_user_id)` | `GET /bundle/sync/{userId}` | Read-only profile and identity key lookup without consuming OPKs |
| `disconnect()` | MQTT Client | Waits for in-flight PUBACKs and gracefully terminates connection |
| `user_id()` | Local State | Returns authenticated user ID |
| `device_id()` | Local State | Returns registered device ID |

### `oauth` Module

| Function | Description |
|---|---|
| `generate_code_verifier()` | Generates a cryptographically random URL-safe PKCE code verifier |
| `generate_code_challenge(verifier)` | Generates SHA-256 code challenge for PKCE S256 |
| `build_google_auth_url(client_id, redirect, challenge, scopes)` | Builds Google OAuth authorization URL |

---

## Cryptographic Security

- **X3DH (Extended Triple Diffie-Hellman)**: Initiates forward-secret sessions between parties, combining Identity Keys, Signed Pre-Keys, and One-Time Pre-Keys.
- **Double Ratchet**: Continuous key derivation for every message exchange; compromise of a single key reveals neither past nor future messages.
- **VXEdDSA & VRF**: Zero-trust authentication where every REST request and MQTT connection attempt is cryptographically verifiable using public keys.
- **Constant-Time Operations**: Cryptographic primitives provided by `libsignal-dezire` and `ed25519-dalek` defend against side-channel timing attacks.

---

## License

This project is licensed under the **GNU Affero General Public License v3.0 (AGPLv3)**.
