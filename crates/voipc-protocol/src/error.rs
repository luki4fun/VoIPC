use thiserror::Error;

#[derive(Debug, Error)]
pub enum ProtocolError {
    #[error("packet too short: expected at least {expected} bytes, got {got}")]
    PacketTooShort { expected: usize, got: usize },

    #[error("unknown UDP packet type: 0x{0:02x}")]
    UnknownPacketType(u8),

    #[error("message too large: {0} bytes (max 65536)")]
    MessageTooLarge(usize),

    #[error("serialization error: {0}")]
    Serialization(#[from] postcard::Error),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn packet_too_short_display() {
        let e = ProtocolError::PacketTooShort { expected: 17, got: 5 };
        let msg = e.to_string();
        assert!(msg.contains("17"));
        assert!(msg.contains("5"));
    }

    #[test]
    fn unknown_packet_type_display() {
        let e = ProtocolError::UnknownPacketType(0xAB);
        let msg = e.to_string();
        assert!(msg.contains("0xab"));
    }

    #[test]
    fn message_too_large_display() {
        let e = ProtocolError::MessageTooLarge(100000);
        let msg = e.to_string();
        assert!(msg.contains("100000"));
    }

    #[test]
    fn from_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::BrokenPipe, "broken");
        let proto_err: ProtocolError = io_err.into();
        assert!(proto_err.to_string().contains("broken"));
    }
}
