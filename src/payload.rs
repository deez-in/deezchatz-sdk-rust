use thiserror::Error;

/// Discriminator byte for UTF-8 text messages.
pub const PAYLOAD_TYPE_TEXT: u8 = 0;

/// Discriminator byte for raw voice/audio messages.
pub const PAYLOAD_TYPE_VOICE: u8 = 1;

/// Discriminator byte for framed image messages.
pub const PAYLOAD_TYPE_IMAGE: u8 = 2;

/// Errors that can occur during payload decoding.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum PayloadError {
    #[error("Cannot decode empty message payload")]
    EmptyPayload,

    #[error("Invalid image payload: header too short")]
    ImageHeaderTooShort,

    #[error("Invalid image payload: payload shorter than caption length")]
    ImagePayloadTooShort,

    #[error("Invalid UTF-8 sequence: {0}")]
    InvalidUtf8(#[from] std::string::FromUtf8Error),

    #[error("Unrecognized message payload type byte: {0}")]
    UnrecognizedType(u8),
}

/// Represents a decoded higher-order message payload.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedPayload {
    /// Plain text message
    Text { text: String },
    /// Voice message with raw audio bytes (e.g., Opus)
    Voice { audio_bytes: Vec<u8> },
    /// Image message with timestamp, caption, and raw image bytes (e.g., JPEG)
    Image {
        timestamp: u32,
        caption: String,
        image_bytes: Vec<u8>,
    },
}

impl DecodedPayload {
    /// Encodes this payload into framed binary bytes matching the deezchatz-mobile format.
    pub fn encode(&self) -> Vec<u8> {
        match self {
            DecodedPayload::Text { text } => encode_text_payload(text),
            DecodedPayload::Voice { audio_bytes } => encode_voice_payload(audio_bytes),
            DecodedPayload::Image {
                timestamp,
                caption,
                image_bytes,
            } => encode_image_payload(*timestamp, caption, image_bytes),
        }
    }
}

/// Encodes a text message string into framed binary bytes: `[0x00, ...utf8Bytes]`.
pub fn encode_text_payload(text: &str) -> Vec<u8> {
    let text_bytes = text.as_bytes();
    let mut payload = Vec::with_capacity(1 + text_bytes.len());
    payload.push(PAYLOAD_TYPE_TEXT);
    payload.extend_from_slice(text_bytes);
    payload
}

/// Encodes raw Opus audio bytes into framed binary bytes: `[0x01, ...audioBytes]`.
pub fn encode_voice_payload(audio_bytes: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(1 + audio_bytes.len());
    payload.push(PAYLOAD_TYPE_VOICE);
    payload.extend_from_slice(audio_bytes);
    payload
}

/// Encodes an image into framed binary bytes:
/// `[0x02, 4-byte timestamp BE, 2-byte caption length BE, caption UTF-8 bytes, raw JPEG bytes]`
pub fn encode_image_payload(timestamp_seconds: u32, caption: &str, image_bytes: &[u8]) -> Vec<u8> {
    let raw_caption_bytes = caption.as_bytes();
    let caption_len = u16::try_from(raw_caption_bytes.len()).unwrap_or(u16::MAX);
    let caption_bytes = &raw_caption_bytes[..caption_len as usize];

    let total_len = 1 + 4 + 2 + caption_bytes.len() + image_bytes.len();
    let mut payload = Vec::with_capacity(total_len);

    payload.push(PAYLOAD_TYPE_IMAGE);
    payload.extend_from_slice(&timestamp_seconds.to_be_bytes());
    payload.extend_from_slice(&caption_len.to_be_bytes());
    payload.extend_from_slice(caption_bytes);
    payload.extend_from_slice(image_bytes);

    payload
}

/// Decodes a framed binary payload by inspecting its first discriminator byte.
///
/// Returns an error if the payload is empty, if the header or caption is truncated,
/// or if an unrecognized type byte is encountered.
pub fn decode_payload(bytes: &[u8]) -> Result<DecodedPayload, PayloadError> {
    if bytes.is_empty() {
        return Err(PayloadError::EmptyPayload);
    }

    let type_byte = bytes[0];

    match type_byte {
        PAYLOAD_TYPE_TEXT => {
            let text = String::from_utf8(bytes[1..].to_vec())?;
            Ok(DecodedPayload::Text { text })
        }
        PAYLOAD_TYPE_VOICE => Ok(DecodedPayload::Voice {
            audio_bytes: bytes[1..].to_vec(),
        }),
        PAYLOAD_TYPE_IMAGE => {
            if bytes.len() < 7 {
                return Err(PayloadError::ImageHeaderTooShort);
            }
            let timestamp = u32::from_be_bytes([bytes[1], bytes[2], bytes[3], bytes[4]]);
            let caption_length = u16::from_be_bytes([bytes[5], bytes[6]]) as usize;

            if bytes.len() < 7 + caption_length {
                return Err(PayloadError::ImagePayloadTooShort);
            }

            let caption_bytes = &bytes[7..7 + caption_length];
            let caption = String::from_utf8(caption_bytes.to_vec())?;
            let image_bytes = bytes[7 + caption_length..].to_vec();

            Ok(DecodedPayload::Image {
                timestamp,
                caption,
                image_bytes,
            })
        }
        other => Err(PayloadError::UnrecognizedType(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_text_payload_ascii() {
        let text = "Hello, world!";
        let payload = encode_text_payload(text);

        assert_eq!(payload[0], PAYLOAD_TYPE_TEXT);
        assert_eq!(payload[0], 0x00);
        assert_eq!(&payload[1..], text.as_bytes());
    }

    #[test]
    fn test_encode_text_payload_empty() {
        let payload = encode_text_payload("");
        assert_eq!(payload.len(), 1);
        assert_eq!(payload[0], PAYLOAD_TYPE_TEXT);
    }

    #[test]
    fn test_encode_text_payload_unicode_and_emojis() {
        let text = "Voice notes rock! 🎤🔥";
        let payload = encode_text_payload(text);
        assert_eq!(payload[0], PAYLOAD_TYPE_TEXT);
        assert_eq!(&payload[1..], text.as_bytes());
    }

    #[test]
    fn test_encode_voice_payload() {
        let raw_audio = vec![0x4f, 0x67, 0x67, 0x53, 0x00, 0x02];
        let payload = encode_voice_payload(&raw_audio);

        assert_eq!(payload[0], PAYLOAD_TYPE_VOICE);
        assert_eq!(payload[0], 0x01);
        assert_eq!(payload.len(), raw_audio.len() + 1);
        assert_eq!(&payload[1..], &raw_audio[..]);
    }

    #[test]
    fn test_encode_voice_payload_empty() {
        let payload = encode_voice_payload(&[]);
        assert_eq!(payload.len(), 1);
        assert_eq!(payload[0], PAYLOAD_TYPE_VOICE);
    }

    #[test]
    fn test_encode_image_payload() {
        let timestamp = 1726030464u32;
        let caption = "sunset 🌅";
        let image_bytes = vec![0xff, 0xd8, 0xff, 0xe0, 0x12, 0x34];

        let payload = encode_image_payload(timestamp, caption, &image_bytes);

        assert_eq!(payload[0], PAYLOAD_TYPE_IMAGE);
        assert_eq!(payload[0], 0x02);

        let ts = u32::from_be_bytes([payload[1], payload[2], payload[3], payload[4]]);
        assert_eq!(ts, timestamp);

        let cap_len = u16::from_be_bytes([payload[5], payload[6]]) as usize;
        assert_eq!(cap_len, caption.len());

        let decoded_caption = std::str::from_utf8(&payload[7..7 + cap_len]).unwrap();
        assert_eq!(decoded_caption, caption);

        assert_eq!(&payload[7 + cap_len..], &image_bytes[..]);
    }

    #[test]
    fn test_encode_image_payload_empty_caption() {
        let timestamp = 1726030464u32;
        let caption = "";
        let image_bytes = vec![0xff, 0xd8];

        let payload = encode_image_payload(timestamp, caption, &image_bytes);

        assert_eq!(payload[0], PAYLOAD_TYPE_IMAGE);
        let cap_len = u16::from_be_bytes([payload[5], payload[6]]) as usize;
        assert_eq!(cap_len, 0);
        assert_eq!(&payload[7..], &image_bytes[..]);
    }

    #[test]
    fn test_decode_valid_text() {
        let original_text = "Test message";
        let encoded = encode_text_payload(original_text);

        let result = decode_payload(&encoded).unwrap();
        match result {
            DecodedPayload::Text { text } => assert_eq!(text, original_text),
            _ => panic!("Expected DecodedPayload::Text"),
        }
    }

    #[test]
    fn test_decode_valid_voice() {
        let original_audio = vec![10, 20, 30, 40, 50];
        let encoded = encode_voice_payload(&original_audio);

        let result = decode_payload(&encoded).unwrap();
        match result {
            DecodedPayload::Voice { audio_bytes } => assert_eq!(audio_bytes, original_audio),
            _ => panic!("Expected DecodedPayload::Voice"),
        }
    }

    #[test]
    fn test_decode_valid_image() {
        let timestamp = 1726030464u32;
        let caption = "Look at this! 📸";
        let image_bytes = vec![0xff, 0xd8, 0xff, 0xdb];
        let encoded = encode_image_payload(timestamp, caption, &image_bytes);

        let result = decode_payload(&encoded).unwrap();
        match result {
            DecodedPayload::Image {
                timestamp: ts,
                caption: cap,
                image_bytes: img,
            } => {
                assert_eq!(ts, timestamp);
                assert_eq!(cap, caption);
                assert_eq!(img, image_bytes);
            }
            _ => panic!("Expected DecodedPayload::Image"),
        }
    }

    #[test]
    fn test_decode_empty_payload() {
        let err = decode_payload(&[]).unwrap_err();
        assert_eq!(err, PayloadError::EmptyPayload);
        assert_eq!(err.to_string(), "Cannot decode empty message payload");
    }

    #[test]
    fn test_decode_truncated_image_header() {
        let truncated = vec![0x02, 0x01, 0x02];
        let err = decode_payload(&truncated).unwrap_err();
        assert_eq!(err, PayloadError::ImageHeaderTooShort);
        assert_eq!(err.to_string(), "Invalid image payload: header too short");
    }

    #[test]
    fn test_decode_image_shorter_than_caption_length() {
        let mut payload = vec![0u8; 8];
        payload[0] = 0x02;
        payload[1..5].copy_from_slice(&1000u32.to_be_bytes());
        payload[5..7].copy_from_slice(&10u16.to_be_bytes()); // Claims caption len is 10, total len only 8

        let err = decode_payload(&payload).unwrap_err();
        assert_eq!(err, PayloadError::ImagePayloadTooShort);
        assert_eq!(
            err.to_string(),
            "Invalid image payload: payload shorter than caption length"
        );
    }

    #[test]
    fn test_decode_unrecognized_type() {
        let invalid_payload = vec![0x05, 0x01, 0x02];
        let err = decode_payload(&invalid_payload).unwrap_err();
        assert_eq!(err, PayloadError::UnrecognizedType(5));
        assert_eq!(
            err.to_string(),
            "Unrecognized message payload type byte: 5"
        );

        let legacy_ascii_payload = b"Hello legacy";
        let err2 = decode_payload(legacy_ascii_payload).unwrap_err();
        assert_eq!(err2, PayloadError::UnrecognizedType(b'H'));
        assert_eq!(
            err2.to_string(),
            "Unrecognized message payload type byte: 72"
        );
    }

    #[test]
    fn test_decoded_payload_encode_roundtrip() {
        let text_item = DecodedPayload::Text {
            text: "Roundtrip text".into(),
        };
        assert_eq!(decode_payload(&text_item.encode()).unwrap(), text_item);

        let voice_item = DecodedPayload::Voice {
            audio_bytes: vec![1, 2, 3, 4],
        };
        assert_eq!(decode_payload(&voice_item.encode()).unwrap(), voice_item);

        let image_item = DecodedPayload::Image {
            timestamp: 1234567,
            caption: "Roundtrip image".into(),
            image_bytes: vec![9, 8, 7],
        };
        assert_eq!(decode_payload(&image_item.encode()).unwrap(), image_item);
    }
}
