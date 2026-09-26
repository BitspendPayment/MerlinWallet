//! Server-sent events, framed from arbitrary byte chunks.
//!
//! An event is a run of lines ended by a blank line; its payload is the `data:` lines joined with
//! newlines. Comment lines (`:`) and other fields are ignored. A body that is not SSE at all —
//! newline-delimited JSON, which a gateway serving the same stream without SSE would send — is
//! handled too: a block with no `data:` line is taken whole.

#[derive(Default)]
pub struct SseFramer {
    buf: Vec<u8>,
}

impl SseFramer {
    pub fn push(&mut self, chunk: &[u8]) {
        self.buf.extend_from_slice(chunk);
    }

    /// The next complete event's payload, if one has arrived.
    pub fn next(&mut self) -> Option<String> {
        loop {
            let text = std::str::from_utf8(&self.buf).ok()?;
            let normalized_end = find_block_end(text)?;
            let (block, rest_start) = normalized_end;
            let block = text[..block].to_string();
            self.buf.drain(..rest_start);
            if let Some(payload) = payload(&block) {
                return Some(payload);
            }
        }
    }
}

/// End of the first block: (end of its text, start of what follows). A block ends at a blank line —
/// `\n\n` or `\r\n\r\n` — or, for newline-delimited JSON, at a newline after a complete JSON line.
fn find_block_end(text: &str) -> Option<(usize, usize)> {
    let blank = [text.find("\r\n\r\n").map(|i| (i, i + 4)), text.find("\n\n").map(|i| (i, i + 2))]
        .into_iter()
        .flatten()
        .min_by_key(|(i, _)| *i);
    if let Some(found) = blank {
        return Some(found);
    }
    // Newline-delimited JSON: a first line that is a whole JSON value.
    let nl = text.find('\n')?;
    let line = text[..nl].trim_end_matches('\r');
    (line.starts_with('{') && serde_json::from_str::<serde_json::Value>(line).is_ok())
        .then_some((nl, nl + 1))
}

fn payload(block: &str) -> Option<String> {
    let mut data: Vec<&str> = Vec::new();
    let mut other = false;
    for line in block.lines() {
        let line = line.trim_end_matches('\r');
        if let Some(rest) = line.strip_prefix("data:") {
            data.push(rest.strip_prefix(' ').unwrap_or(rest));
        } else if !line.is_empty() && !line.starts_with(':') {
            other = true;
        }
    }
    if !data.is_empty() {
        return Some(data.join("\n"));
    }
    // No `data:` field. Take the block whole if it is JSON; an `event:`/`id:`-only block is not.
    let whole = block.trim();
    (other && whole.starts_with('{')).then(|| whole.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn events_arrive_whole_however_the_bytes_are_split() {
        let stream = b"data: {\"a\":1}\n\n: keepalive\n\ndata: {\"b\":\ndata: 2}\n\n";
        for split in 1..stream.len() {
            let mut f = SseFramer::default();
            let mut out = Vec::new();
            for chunk in stream.chunks(split) {
                f.push(chunk);
                while let Some(e) = f.next() {
                    out.push(e);
                }
            }
            assert_eq!(out, vec!["{\"a\":1}", "{\"b\":\n2}"], "split {split}");
        }
    }

    #[test]
    fn crlf_and_newline_delimited_json_are_understood() {
        let mut f = SseFramer::default();
        f.push(b"data: {\"x\":1}\r\n\r\n{\"y\":2}\n{\"z\":3}\n");
        assert_eq!(f.next().as_deref(), Some("{\"x\":1}"));
        assert_eq!(f.next().as_deref(), Some("{\"y\":2}"));
        assert_eq!(f.next().as_deref(), Some("{\"z\":3}"));
        assert_eq!(f.next(), None);
    }
}
