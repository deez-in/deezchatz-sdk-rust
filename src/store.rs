use async_trait::async_trait;
use serde::{Deserialize, Serialize};
use crate::error::SdkError;

/// Represents an abstract storage backend for cryptographic keys.
///
/// Consumers of the SDK must implement this trait to securely persist the Identity Key,
/// Signed Pre-Key, and One-Time Pre-Keys (OPKs).
#[async_trait]
pub trait KeyStore: Send + Sync {
    /// Save the identity key pair
    async fn save_identity_key(&self, private_key: &[u8; 32], public_key: &[u8; 33]) -> Result<(), SdkError>;
    
    /// Retrieve the identity key pair
    async fn get_identity_key(&self) -> Result<Option<([u8; 32], [u8; 33])>, SdkError>;

    /// Save a signed pre-key
    async fn save_signed_pre_key(&self, id: u32, private_key: &[u8; 32], public_key: &[u8; 33]) -> Result<(), SdkError>;

    /// Get a signed pre-key by ID
    async fn get_signed_pre_key(&self, id: u32) -> Result<Option<([u8; 32], [u8; 33])>, SdkError>;

    /// Save a batch of one-time pre-keys
    async fn save_one_time_pre_keys(&self, keys: Vec<(u32, [u8; 32], [u8; 33])>) -> Result<(), SdkError>;

    /// Remove and return a one-time pre-key by ID
    async fn consume_one_time_pre_key(&self, id: u32) -> Result<Option<([u8; 32], [u8; 33])>, SdkError>;
}

/// Represents an abstract storage backend for Signal Protocol sessions.
///
/// Consumers of the SDK must implement this trait to persist Double Ratchet sessions.
#[async_trait]
pub trait SessionStore: Send + Sync {
    /// Save a serialized session state for a specific recipient
    async fn save_session(&self, recipient_id: &str, session_data: &[u8]) -> Result<(), SdkError>;

    /// Retrieve a serialized session state for a specific recipient
    async fn get_session(&self, recipient_id: &str) -> Result<Option<Vec<u8>>, SdkError>;

    /// Delete a session
    async fn delete_session(&self, recipient_id: &str) -> Result<(), SdkError>;
}

// ---------------------------------------------------------------------------
// Inbox & Outbox Persistence (Persistent Queuing)
// ---------------------------------------------------------------------------

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageStatus {
    Pending,
    Processed,
    Sent,
    Failed,
}

/// Represents a persistent entry in the raw incoming MQTT Inbox.
///
/// Ensures incoming ciphertexts are saved to disk *before* decryption attempts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct InboxEntry {
    pub id: i64,
    pub topic: String,
    pub payload: Vec<u8>,
    pub received_at: u64,
    pub status: MessageStatus,
    pub retry_count: u32,
    pub processed_at: Option<u64>,
}

/// Abstract storage backend for the incoming message Inbox queue.
#[async_trait]
pub trait InboxStore: Send + Sync {
    /// Writes a raw incoming MQTT payload immediately to disk before any crypto processing.
    async fn save_to_inbox(&self, topic: &str, payload: &[u8]) -> Result<i64, SdkError>;

    /// Marks an inbox entry as successfully decrypted and delivered to the application layer.
    async fn mark_inbox_processed(&self, id: i64) -> Result<(), SdkError>;

    /// Marks an inbox entry as failed (e.g. invalid signature, corrupted payload) or increments retry count.
    async fn mark_inbox_failed(&self, id: i64, error: &str) -> Result<(), SdkError>;

    /// Retrieves all pending/unprocessed inbox entries to replay on resume or reconnect.
    async fn get_pending_inbox(&self) -> Result<Vec<InboxEntry>, SdkError>;
}

/// Represents a persistent entry in the outgoing MQTT Outbox.
///
/// Ensures outbound messages are saved to disk *before* MQTT publish attempts.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OutboxEntry {
    pub id: i64,
    pub recipient_id: String,
    pub message_id: String,
    pub topic: String,
    pub payload: Vec<u8>,
    pub created_at: u64,
    pub status: MessageStatus,
    pub retry_count: u32,
    pub sent_at: Option<u64>,
}

/// Abstract storage backend for the outgoing message Outbox queue.
#[async_trait]
pub trait OutboxStore: Send + Sync {
    /// Saves an encrypted message payload to the outbox queue before attempting MQTT publish.
    async fn save_to_outbox(
        &self,
        recipient_id: &str,
        message_id: &str,
        topic: &str,
        payload: &[u8],
    ) -> Result<i64, SdkError>;

    /// Marks an outbox entry as successfully published to the MQTT broker.
    async fn mark_outbox_sent(&self, id: i64) -> Result<(), SdkError>;

    /// Marks an outbox entry as failed or increments retry count.
    async fn mark_outbox_failed(&self, id: i64, error: &str) -> Result<(), SdkError>;

    /// Retrieves all pending outbox entries waiting to be published upon reconnection.
    async fn get_pending_outbox(&self) -> Result<Vec<OutboxEntry>, SdkError>;
}
