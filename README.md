# DeezChatz SDK Rust 🦀

[![Rust](https://img.shields.io/badge/Rust-1.75%2B-orange.svg)](https://www.rust-lang.org/)
[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-orange.svg)](https://www.gnu.org/licenses/agpl-3.0)

The **deezchatz-sdk-rust** is a programmatic, fully asynchronous Rust client for the DeezChatz ecosystem. It abstracts away the complexities of the Signal Protocol (X3DH, Double Ratchet), VXEdDSA REST authentication, and real-time MQTT networking. 

This SDK is intended for developers building CLI clients, bots, or desktop apps that need to interface with the DeezChatz API securely.

## Features

- **Automated Cryptography**: Deeply integrated with `libsignal-dezire` to handle Identity Keys, Signed Pre-Keys, OPKs, and Double Ratchet encryption/decryption seamlessly.
- **Stateless REST Authentication**: Automatically calculates VXEdDSA signatures and VRF proofs for all authenticated API requests.
- **Event-Driven MQTT**: Manages persistent MQTT background connections and exposes an easy-to-use asynchronous `tokio::sync::mpsc::Receiver` for real-time events.
- **Bring-Your-Own-Storage (BYOS)**: Define your own persistence layer (e.g., SQLite, Redis, or File System) by implementing the simple `KeyStore`, `SessionStore`, `InboxStore`, and `OutboxStore` traits.

---

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
deezchatz-sdk-rust = { path = "../deezchatz-sdk-rust" }
tokio = { version = "1", features = ["full"] }
```

## Quick Start

### 1. Implement Storage Traits

The SDK uses a **Bring-Your-Own-Storage (BYOS)** model. You implement the storage traits using your preferred persistent backend (e.g. SQLite, SQLCipher, Sled):

- `KeyStore`: Persists Curve25519 identity keys, signed pre-keys, and OPKs.
- `SessionStore`: Persists Double Ratchet session states for active chats.
- `InboxStore`: Persists raw incoming MQTT ciphertexts immediately on arrival to prevent message loss across process crashes/kills.
- `OutboxStore`: Persists outgoing ciphertexts as `Pending` before transmission, automatically retrying/flushing when reconnected.

```rust
use async_trait::async_trait;
use deezchatz_sdk_rust::store::{KeyStore, SessionStore, InboxStore, OutboxStore};
use deezchatz_sdk_rust::SdkError;

pub struct MySqliteStore { /* ... */ }

// Implement KeyStore, SessionStore, InboxStore, OutboxStore for MySqliteStore
```

### 2. Initialize the Client and Register

You can register new devices using either **Google OAuth 2.0 PKCE Authorization Code** (recommended for CLIs and web apps) or a Google OAuth ID Token:

#### Using OAuth PKCE (Recommended for CLI / Native Apps):
```rust
use std::sync::Arc;
use deezchatz_sdk_rust::{DeezChatzClient, ClientConfig, pkce};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Presets available: ClientConfig::production(), ClientConfig::development(), ClientConfig::from_env()
    let config = ClientConfig::production();

    let keystore = Arc::new(MySqliteStore::new());
    let sessionstore = Arc::new(MySqliteStore::new());
    let inboxstore = Arc::new(MySqliteStore::new());
    let outboxstore = Arc::new(MySqliteStore::new());
    let mut client = DeezChatzClient::new(config, keystore, sessionstore, inboxstore, outboxstore);

    // 1. Generate PKCE code verifier and S256 challenge
    let verifier = pkce::generate_code_verifier();
    let challenge = pkce::generate_code_challenge(&verifier);

    // 2. Open Google OAuth URL for user authentication
    let auth_url = pkce::build_google_auth_url(
        "YOUR_GOOGLE_CLIENT_ID",
        "http://localhost:8080/callback",
        &challenge,
        &["openid", "email", "profile"],
    );
    println!("Please log in via: {}", auth_url);

    // 3. After receiving the auth code from the callback:
    let auth_code = "4/0AeaYSH...";
    client.register_with_pkce(
        auth_code,
        Some(&verifier),
        "http://localhost:8080/callback",
        "+1234567890",
        None, // Optional FCM device token
    ).await?;
    
    println!("Registered successfully via PKCE!");
    Ok(())
}
```

### 3. Connect to MQTT and Send Messages

To send and receive real-time messages, establish the background MQTT connection. The SDK takes care of X3DH session establishment automatically when sending a message to a new contact.

```rust
use deezchatz_sdk_rust::Event;

// Connect to the MQTT broker
let mut receiver = client.connect("my-user-id", "my-device-id").await?;

// Spawn a background task to process incoming real-time events
tokio::spawn(async move {
    while let Some(event) = receiver.recv().await {
        match event {
            Event::MessageReceived { sender, plaintext } => {
                println!("💬 New message from {}: {}", sender, plaintext);
            }
            Event::Connected => {
                println!("🌐 Connected to DeezChatz Broker");
            }
            Event::Disconnected => {
                println!("⚠️ Disconnected from broker");
            }
        }
    }
});

// Send an end-to-end encrypted message
// If no session exists, the SDK will transparently fetch the recipient's pre-key bundle, 
// perform the X3DH key agreement, and encrypt the message via the Double Ratchet.
client.send_message("recipient@example.com", "Hello from the Rust SDK!").await?;
```

---

## API Method Reference

`DeezChatzClient` exposes methods for core messaging operations:

| Method | Backend Endpoint | Description |
|---|---|---|
| `register_with_pkce(...)` | `POST /register/google/pkce`<br/>`POST /register/device` | Complete registration via OAuth 2.0 PKCE auth code & uploads signed keys |
| `register(...)` | `POST /register/google/id_token`<br/>`POST /register/device` | Complete registration via Google ID Token & uploads signed keys |
| `connect(...)` | RMQTT Broker (`/deezchatz/...`) | Connects to MQTT broker using signature-auth password; returns event receiver |
| `send_message(...)` | `POST /bundle/{id}` + MQTT | Sends end-to-end encrypted message (handles X3DH session fallback automatically) |
| `get_sync_bundle(userId)` | `GET /bundle/sync/{userId}` | Read-only profile and identity key lookup without consuming pre-keys |

---

## Architecture and Cryptography

The SDK aligns precisely with the official [Signal Protocol Specifications](https://signal.org/docs/):

- **X3DH (Extended Triple Diffie-Hellman)**: When `send_message` encounters a contact for the first time, it fetches their pre-key bundle (Identity Key, Signed Pre-Key, and OPK) and calculates a shared secret.
- **Double Ratchet**: All outbound and inbound messages are encrypted using a new, unique message key, providing both forward and backward secrecy.
- **VXEdDSA**: To achieve a zero-trust architecture, all REST requests sent by the `ApiClient` are cryptographically signed using the client's Identity Key. This eliminates the need for vulnerable JWTs or session cookies.

---

## License

This project is licensed under the **GNU Affero General Public License v3.0 (AGPLv3)**.
