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

    #[error("VXEdDSA error: {0:?}")]
    VxEdDsa(libsignal_dezire::vxeddsa::VXEdDSAError),

    #[error("X3DH error: {0:?}")]
    X3dh(libsignal_dezire::x3dh::X3DHError),

    #[error("Storage error: {0}")]
    Storage(String),

    #[error("Invalid operation: {0}")]
    InvalidOperation(String),

    #[error("Payload error: {0}")]
    Payload(#[from] crate::messaging::PayloadError),
}

impl From<libsignal_dezire::vxeddsa::VXEdDSAError> for SdkError {
    fn from(e: libsignal_dezire::vxeddsa::VXEdDSAError) -> Self {
        SdkError::VxEdDsa(e)
    }
}

impl From<libsignal_dezire::x3dh::X3DHError> for SdkError {
    fn from(e: libsignal_dezire::x3dh::X3DHError) -> Self {
        SdkError::X3dh(e)
    }
}
