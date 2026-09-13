//! gRPC's message framing, which is five bytes.
//!
//! One compression flag, then a big-endian `u32` length, then the message. Frames do not align
//! with HTTP/2 DATA frames in either direction — a frame may arrive split across several reads,
//! and several may arrive in one — so this is the only place allowed to assume anything about
//! where they begin.
//!
//! This is what tonic was providing. It is worth writing out rather than depending on, because
//! tonic does not build for `wasm32-wasip2` at all and this is the part of it the cosigner needed.

use bytes::{BufMut, Bytes, BytesMut};

/// Larger than any message this service has a use for.
///
/// The ceiling has to live here. The runtime bounds an ordinary request body because it hashes it,
/// but a stream is never hashed and never buffered, so nothing upstream is counting: the guest is
/// the only thing between a client and an allocation as large as it cares to claim.
///
/// Sized for the largest real message, which is a settle's relayed `GetEventStreamResponse` — an
/// ASP batch round carries a whole VTXO tree in one event.
pub const MAX_MESSAGE_BYTES: usize = 4 * 1024 * 1024;

#[derive(Debug, PartialEq, Eq)]
pub enum Malformed {
    /// We advertise no compression, so a frame claiming it is a client bug.
    Compressed,
    TooLarge(usize),
}

impl std::fmt::Display for Malformed {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Malformed::Compressed => write!(f, "compressed frames are not accepted"),
            Malformed::TooLarge(n) => {
                write!(f, "a {n} byte message exceeds the {MAX_MESSAGE_BYTES} byte limit")
            }
        }
    }
}

/// Wrap one encoded message for the wire.
pub fn frame(message: &[u8]) -> Bytes {
    let mut out = BytesMut::with_capacity(5 + message.len());
    out.put_u8(0);
    out.put_u32(message.len() as u32);
    out.put_slice(message);
    out.freeze()
}

/// Reassembles messages from however the bytes happen to arrive.
#[derive(Debug, Default)]
pub struct Deframer {
    buffer: BytesMut,
}

impl Deframer {
    pub fn push(&mut self, data: &[u8]) {
        self.buffer.extend_from_slice(data);
    }

    pub fn is_empty(&self) -> bool {
        self.buffer.is_empty()
    }

    /// The next complete message, if one has fully arrived.
    pub fn next(&mut self) -> Result<Option<Bytes>, Malformed> {
        if self.buffer.len() < 5 {
            return Ok(None);
        }
        if self.buffer[0] != 0 {
            return Err(Malformed::Compressed);
        }
        let len = u32::from_be_bytes([self.buffer[1], self.buffer[2], self.buffer[3], self.buffer[4]])
            as usize;
        if len > MAX_MESSAGE_BYTES {
            return Err(Malformed::TooLarge(len));
        }
        if self.buffer.len() < 5 + len {
            return Ok(None);
        }
        let _ = self.buffer.split_to(5);
        Ok(Some(self.buffer.split_to(len).freeze()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_message_split_across_reads_is_reassembled() {
        let whole = frame(b"hello world");
        let mut d = Deframer::default();
        // Three reads, none of them on a frame boundary.
        d.push(&whole[..3]);
        assert_eq!(d.next().unwrap(), None);
        d.push(&whole[3..9]);
        assert_eq!(d.next().unwrap(), None);
        d.push(&whole[9..]);
        assert_eq!(d.next().unwrap().as_deref(), Some(&b"hello world"[..]));
        assert_eq!(d.next().unwrap(), None);
        assert!(d.is_empty());
    }

    #[test]
    fn several_messages_in_one_read_all_come_out() {
        let mut d = Deframer::default();
        let mut buf = Vec::new();
        buf.extend_from_slice(&frame(b"one"));
        buf.extend_from_slice(&frame(b"two"));
        buf.extend_from_slice(&frame(b"three"));
        d.push(&buf);
        assert_eq!(d.next().unwrap().as_deref(), Some(&b"one"[..]));
        assert_eq!(d.next().unwrap().as_deref(), Some(&b"two"[..]));
        assert_eq!(d.next().unwrap().as_deref(), Some(&b"three"[..]));
        assert_eq!(d.next().unwrap(), None);
    }

    /// A truncated frame must stay in the buffer rather than being reported as absent — the
    /// difference is what tells a half-close from a cut-off message.
    #[test]
    fn a_truncated_frame_is_held_not_dropped() {
        let whole = frame(b"hello");
        let mut d = Deframer::default();
        d.push(&whole[..7]);
        assert_eq!(d.next().unwrap(), None);
        assert!(!d.is_empty());
    }

    #[test]
    fn compression_and_oversize_are_refused() {
        let mut d = Deframer::default();
        d.push(&[1, 0, 0, 0, 1, 0xff]);
        assert_eq!(d.next(), Err(Malformed::Compressed));

        let mut d = Deframer::default();
        let too_big = (MAX_MESSAGE_BYTES + 1) as u32;
        let mut head = vec![0u8];
        head.extend_from_slice(&too_big.to_be_bytes());
        d.push(&head);
        assert_eq!(d.next(), Err(Malformed::TooLarge(MAX_MESSAGE_BYTES + 1)));
    }
}
