use thiserror::Error;

/// The unified error type for the DeezChatz SDK.
#[derive(Error, Debug)]
pub enum SdkError {
    #[error("API error: {0}")]
    Api(String),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("MQTT error: {0}")]
    Mqtt(String),

    #[error("Crypto error: {0}")]
    Crypto(String),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Invalid operation: {0}")]
    InvalidOperation(String),
}
