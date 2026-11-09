//! Incremental Server-Sent Events parser and encoder.
//!
//! Follows the WHATWG event-stream rules: lines end in CRLF, LF or a lone CR,
//! a blank line dispatches the event, lines starting with `:` are comments,
//! one leading space after the field colon is stripped, and multiple `data:`
//! lines are joined with `\n`. Chunks may split lines (and CRLF pairs) at any
//! byte. Memory is bounded: a line or event larger than the configured limit
//! is dropped and [`SseParser::overflowed`] is set.

/// Default bound for buffered bytes (partial line plus pending event data).
pub const DEFAULT_MAX_BUFFER: usize = 4 * 1024 * 1024;

/// One dispatched SSE event.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SseEvent {
    /// `event:` field (event type), if the event set one.
    pub event: Option<String>,
    /// `id:` field, if the event set one.
    pub id: Option<String>,
    /// Joined `data:` lines.
    pub data: String,
}

impl SseEvent {
    /// Event with only a `data` payload.
    pub fn data(data: impl Into<String>) -> Self {
        Self { event: None, id: None, data: data.into() }
    }
}

/// Incremental SSE parser. Feed raw response chunks, get complete events.
#[derive(Debug)]
pub struct SseParser {
    buf: Vec<u8>,
    event: Option<String>,
    id: Option<String>,
    data: String,
    has_data: bool,
    max: usize,
    started: bool,
    overflowed: bool,
    skip_line: bool,
    skip_event: bool,
}

impl Default for SseParser {
    fn default() -> Self {
        Self::new()
    }
}

impl SseParser {
    /// Parser with the default 4 MiB buffer bound.
    pub fn new() -> Self {
        Self::with_limit(DEFAULT_MAX_BUFFER)
    }

    /// Parser with a custom bound on buffered bytes.
    pub fn with_limit(max: usize) -> Self {
        Self {
            buf: Vec::new(),
            event: None,
            id: None,
            data: String::new(),
            has_data: false,
            max: max.max(1),
            started: false,
            overflowed: false,
            skip_line: false,
            skip_event: false,
        }
    }

    /// True once any line or event was dropped for exceeding the bound.
    pub fn overflowed(&self) -> bool {
        self.overflowed
    }

    /// Feed a chunk and return every event it completes.
    pub fn feed(&mut self, chunk: &[u8]) -> Vec<SseEvent> {
        let mut out = Vec::new();
        self.buf.extend_from_slice(chunk);
        if !self.started {
            // Strip a UTF-8 BOM at the very start of the stream.
            if self.buf.len() < 3 && b"\xEF\xBB\xBF".starts_with(&self.buf) {
                return out;
            }
            if self.buf.starts_with(b"\xEF\xBB\xBF") {
                self.buf.drain(..3);
            }
            self.started = true;
        }
        let mut start = 0usize;
        while let Some(rel) = memchr::memchr2(b'\n', b'\r', &self.buf[start..]) {
            let end = start + rel;
            let next = if self.buf[end] == b'\r' {
                match self.buf.get(end + 1) {
                    Some(b'\n') => end + 2,
                    Some(_) => end + 1,
                    // A CR at the end of the buffer may be the first half of a CRLF.
                    None => break,
                }
            } else {
                end + 1
            };
            let line = std::mem::take(&mut self.buf);
            self.process_line(&line[start..end], &mut out);
            self.buf = line;
            start = next;
        }
        self.buf.drain(..start);
        if self.buf.len() > self.max {
            // Oversized partial line: drop it and everything up to its end.
            self.buf.clear();
            self.skip_line = true;
            self.overflowed = true;
        }
        out
    }

    /// End of stream: dispatch a final event that lacked its trailing blank
    /// line. Strict SSE discards it, but several LLM gateways omit the last
    /// blank line, so callers may opt in to keeping it.
    pub fn finish(mut self) -> Option<SseEvent> {
        if !self.buf.is_empty() && !self.skip_line {
            let line = std::mem::take(&mut self.buf);
            let line = line.strip_suffix(b"\r").unwrap_or(&line);
            let mut sink = Vec::new();
            self.process_line(line, &mut sink);
        }
        self.dispatch()
    }

    fn process_line(&mut self, line: &[u8], out: &mut Vec<SseEvent>) {
        if self.skip_line {
            // Tail of a line that already overflowed.
            self.skip_line = false;
            return;
        }
        if line.is_empty() {
            if self.skip_event {
                self.skip_event = false;
                self.reset();
                return;
            }
            if let Some(ev) = self.dispatch() {
                out.push(ev);
            }
            return;
        }
        if line[0] == b':' || self.skip_event {
            return;
        }
        let line = String::from_utf8_lossy(line);
        let (field, value) = match line.find(':') {
            Some(i) => {
                let v = &line[i + 1..];
                (&line[..i], v.strip_prefix(' ').unwrap_or(v))
            }
            None => (&line[..], ""),
        };
        match field {
            "data" => {
                if self.data.len() + value.len() + 1 > self.max {
                    self.overflowed = true;
                    self.skip_event = true;
                    self.reset();
                    return;
                }
                if self.has_data {
                    self.data.push('\n');
                }
                self.data.push_str(value);
                self.has_data = true;
            }
            "event" => self.event = Some(value.to_string()),
            "id" if !value.contains('\0') => self.id = Some(value.to_string()),
            _ => {}
        }
    }

    fn dispatch(&mut self) -> Option<SseEvent> {
        if !self.has_data {
            self.reset();
            return None;
        }
        let ev = SseEvent { event: self.event.take(), id: self.id.take(), data: std::mem::take(&mut self.data) };
        self.reset();
        Some(ev)
    }

    fn reset(&mut self) {
        self.event = None;
        self.id = None;
        self.data.clear();
        self.has_data = false;
    }
}

/// Encode an event in wire format, terminated by a blank line. CR and LF in
/// `event` and `id` are removed so a rewritten value cannot inject fields.
pub fn encode(ev: &SseEvent) -> String {
    let mut out = String::with_capacity(ev.data.len() + 32);
    let clean = |s: &str| s.chars().filter(|c| *c != '\r' && *c != '\n').collect::<String>();
    if let Some(e) = &ev.event {
        out.push_str("event: ");
        out.push_str(&clean(e));
        out.push('\n');
    }
    if let Some(id) = &ev.id {
        out.push_str("id: ");
        out.push_str(&clean(id));
        out.push('\n');
    }
    let data = ev.data.replace("\r\n", "\n").replace('\r', "\n");
    for line in data.split('\n') {
        out.push_str("data: ");
        out.push_str(line);
        out.push('\n');
    }
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn all(p: &mut SseParser, chunks: &[&[u8]]) -> Vec<SseEvent> {
        chunks.iter().flat_map(|c| p.feed(c)).collect()
    }

    #[test]
    fn parses_basic_fields() {
        let mut p = SseParser::new();
        let evs = p.feed(b"event: message\nid: 7\ndata: {\"a\":1}\n\n");
        assert_eq!(
            evs,
            vec![SseEvent { event: Some("message".into()), id: Some("7".into()), data: "{\"a\":1}".into() }]
        );
    }

    #[test]
    fn handles_lines_split_across_chunks() {
        let mut p = SseParser::new();
        let evs = all(&mut p, &[b"da", b"ta: hel", b"lo\n", b"\n", b"data: x\n\n"]);
        assert_eq!(evs.len(), 2);
        assert_eq!(evs[0].data, "hello");
        assert_eq!(evs[1].data, "x");
    }

    #[test]
    fn handles_crlf_split_between_chunks() {
        let mut p = SseParser::new();
        let evs = all(&mut p, &[b"data: a\r", b"\n\r", b"\ndata: b\r\r\n"]);
        assert_eq!(evs.iter().map(|e| e.data.as_str()).collect::<Vec<_>>(), vec!["a", "b"]);
    }

    #[test]
    fn multi_line_data_and_comments() {
        let mut p = SseParser::new();
        let evs = p.feed(b": keep-alive\ndata: one\ndata:two\ndata\n\n");
        assert_eq!(evs.len(), 1);
        assert_eq!(evs[0].data, "one\ntwo\n");
    }

    #[test]
    fn comment_only_block_dispatches_nothing() {
        let mut p = SseParser::new();
        assert!(p.feed(b":\r\n\r\nevent: ping\n\n").is_empty());
    }

    #[test]
    fn strips_bom_even_when_split() {
        let mut p = SseParser::new();
        let evs = all(&mut p, &[b"\xEF", b"\xBB\xBFdata: x\n\n"]);
        assert_eq!(evs[0].data, "x");
    }

    #[test]
    fn bounded_buffer_drops_oversized_line() {
        let mut p = SseParser::with_limit(16);
        let mut evs = p.feed(b"data: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa");
        evs.extend(p.feed(b"aaaa\n\ndata: ok\n\n"));
        assert!(p.overflowed());
        assert_eq!(evs, vec![SseEvent::data("ok")]);
    }

    #[test]
    fn bounded_event_data() {
        let mut p = SseParser::with_limit(10);
        let evs = p.feed(b"data: 123456\ndata: 789012\n\ndata: z\n\n");
        assert!(p.overflowed());
        assert_eq!(evs, vec![SseEvent::data("z")]);
    }

    #[test]
    fn finish_flushes_unterminated_event() {
        let mut p = SseParser::new();
        assert!(p.feed(b"data: tail").is_empty());
        assert_eq!(p.finish(), Some(SseEvent::data("tail")));
    }

    #[test]
    fn encode_round_trips() {
        let ev = SseEvent { event: Some("message".into()), id: Some("1\n2".into()), data: "a\nb\r\n\nc".into() };
        let wire = encode(&ev);
        assert_eq!(wire, "event: message\nid: 12\ndata: a\ndata: b\ndata: \ndata: c\n\n");
        let mut p = SseParser::new();
        let back = p.feed(wire.as_bytes());
        assert_eq!(back[0].data, "a\nb\n\nc");
        assert_eq!(back[0].id.as_deref(), Some("12"));
        let empty = encode(&SseEvent::data(""));
        assert_eq!(SseParser::new().feed(empty.as_bytes()), vec![SseEvent::data("")]);
    }
}
