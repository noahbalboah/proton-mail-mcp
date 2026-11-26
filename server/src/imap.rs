//! IMAP4rev1 client for Proton Bridge.
//!
//! Every command byte is written by `Conn::write_command`. That function parses the command
//! and refuses anything outside the allowlist, so a caller cannot EXPUNGE, CLOSE, DELETE, or
//! smuggle a second command. `\Deleted` and `UID EXPUNGE` are sent only for a selected
//! `Labels/` mailbox. `APPEND` is sent only to `Drafts`, and only as a synchronizing literal.

use std::io::{Read, Write};
use std::time::{Duration, Instant};

/// Failure from the IMAP client.
///
/// `Server` is a tagged `NO` or `BAD`. Its text is the server's first-line reply, truncated
/// to 200 characters. Passwords and message bodies are never copied into these strings.
#[derive(Debug)]
pub enum Error {
    Io(std::io::Error),
    Protocol(String),
    Server(String),
    InvalidArgument(String),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Error::Io(err) => write!(f, "imap io error: {err}"),
            Error::Protocol(msg) => write!(f, "imap protocol error: {msg}"),
            Error::Server(msg) => write!(f, "imap server error: {msg}"),
            Error::InvalidArgument(msg) => write!(f, "imap invalid argument: {msg}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(err) => Some(err),
            Error::Protocol(_) | Error::Server(_) | Error::InvalidArgument(_) => None,
        }
    }
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}

/// Longest any one command (or the greeting) may take, however the server trickles data. Bridge
/// sends a progress line every few seconds while a command is stuck, which keeps resetting the
/// socket read timeout, so this total limit is what ends a hung command.
pub const COMMAND_DEADLINE: Duration = Duration::from_secs(90);
const MAX_LINE: usize = 64 * 1024;
const MAX_LITERAL: usize = 8 * 1024 * 1024;
const MAX_RESPONSE: usize = 16 * 1024 * 1024;
/// Sum of every response (untagged and tagged) belonging to one command.
const MAX_COMMAND_BYTES: usize = 48 * 1024 * 1024;
const MAX_UNTAGGED: usize = 100_000;
const MAX_DEPTH: usize = 16;
const MAX_LIST_ITEMS: usize = 100_000;
const MAX_FETCH_UIDS: usize = 200;
const MAX_SERVER_CHARS: usize = 200;
/// `BODY.PEEK[HEADER.FIELDS ...]<0.N>` so a hostile header cannot be pulled in full.
const HEADER_PEEK_BYTES: u32 = 65_536;
/// Outbound command cap. Same bound as an inbound line, so a hostile argument cannot force an
/// unbounded write buffer. Two hundred UIDs and any real mailbox name fit comfortably.
const MAX_COMMAND: usize = 64 * 1024;
/// Move, copy, flag, and label updates. Fetch stays at [`MAX_FETCH_UIDS`].
const MAX_WRITE_UIDS: usize = 50;
/// Largest draft `APPEND` will send.
const MAX_APPEND_BYTES: usize = 2 * 1024 * 1024;
/// Largest COPYUID / APPENDUID set expanded from one response. A hostile range must not allocate.
const MAX_COPYUID: usize = 10_000;

fn protocol(msg: &str) -> Error {
    Error::Protocol(msg.to_string())
}

fn invalid(msg: &str) -> Error {
    Error::InvalidArgument(msg.to_string())
}

/// Mailbox selected on this connection, if any.
///
/// Updated only after a tagged `OK` to `EXAMINE` or `SELECT`. Cleared after a successful
/// `UNSELECT`, and after any failed `SELECT` or `EXAMINE` (the previous mailbox is gone).
#[derive(Debug, Clone, PartialEq, Eq)]
enum MailboxState {
    None,
    Examined(String),
    Selected(String),
}

/// What a successful command does to [`MailboxState`].
#[derive(Debug)]
enum MailboxOp {
    Keep,
    Select(String),
    Examine(String),
    Unselect,
}

/// Parsed command, if [`command_allowed`] accepted it.
struct Decision {
    op: MailboxOp,
    /// Byte count of a synchronizing literal this command still has to send.
    literal: Option<usize>,
}

/// One IMAP connection. `S` is the byte stream (a TCP socket, or a test double).
pub struct Conn<S> {
    stream: S,
    /// Bytes already pulled from `stream` and not yet consumed.
    buf: Vec<u8>,
    pos: usize,
    /// Absolute index in `buf` at which the next CRLF search should start.
    /// Bytes before this (and at or after `pos`) have already been scanned.
    scan_from: usize,
    /// Next tag number. Tags are `a1`, `a2`, ...
    next_tag: u64,
    mailbox: MailboxState,
    /// When the command in progress must have finished.
    deadline: Option<Instant>,
}

impl<S: Read + Write> Conn<S> {
    pub fn new(stream: S) -> Self {
        Self {
            stream,
            buf: Vec::new(),
            pos: 0,
            scan_from: 0,
            next_tag: 1,
            mailbox: MailboxState::None,
            deadline: None,
        }
    }

    fn check_deadline(&self) -> Result<(), Error> {
        match self.deadline {
            Some(d) if Instant::now() >= d => Err(Error::Io(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "command took too long",
            ))),
            _ => Ok(()),
        }
    }

    /// Server greeting. Only `* OK` is accepted. `PREAUTH` and `BYE` are errors.
    pub fn read_greeting(&mut self) -> Result<(), Error> {
        self.deadline = Some(Instant::now() + COMMAND_DEADLINE);
        let resp = self.read_response()?;
        if resp.first() == Some(&b'+') || !is_ok_greeting(&resp) {
            return Err(protocol("greeting was not OK"));
        }
        Ok(())
    }

    /// Send one allowlisted command and return its raw untagged responses.
    ///
    /// Response literals stay inline (`{n}` followed by the n bytes). A server `+` continuation
    /// is a protocol error here. `Session::append_draft` is the path that waits for `+`.
    pub fn command(&mut self, cmd: &str) -> Result<Vec<Vec<u8>>, Error> {
        self.transact(cmd, None).map(|(untagged, _)| untagged)
    }

    /// Send `cmd`. When `literal` is set it is written only after the server sends `+`.
    fn transact(
        &mut self,
        cmd: &str,
        literal: Option<&[u8]>,
    ) -> Result<(Vec<Vec<u8>>, Vec<u8>), Error> {
        self.deadline = Some(Instant::now() + COMMAND_DEADLINE);
        let (tag, op) = self.write_command(cmd, literal)?;
        let result = self.finish_command(&tag, literal);
        let ok = result.is_ok();
        self.apply_mailbox_op(op, ok);
        result
    }

    fn finish_command(
        &mut self,
        tag: &str,
        literal: Option<&[u8]>,
    ) -> Result<(Vec<Vec<u8>>, Vec<u8>), Error> {
        let mut untagged = Vec::new();
        let mut used = 0usize;
        if let Some(bytes) = literal {
            let resp = self.read_bounded(&mut used)?;
            if resp.first() != Some(&b'+') {
                return refuse_continuation(tag, &resp);
            }
            self.write_literal(bytes)?;
        }
        loop {
            let resp = self.read_bounded(&mut used)?;
            if resp.first() == Some(&b'+') {
                return Err(protocol("server continuation not supported"));
            }
            if resp.first() == Some(&b'*') {
                if untagged.len() >= MAX_UNTAGGED {
                    return Err(protocol("too many untagged responses"));
                }
                untagged.push(resp);
                continue;
            }
            match tagged_outcome(tag, &resp)? {
                TaggedOutcome::Ok => return Ok((untagged, resp)),
                TaggedOutcome::No(body) => return Err(Error::Server(body)),
            }
        }
    }

    fn read_bounded(&mut self, used: &mut usize) -> Result<Vec<u8>, Error> {
        let room = MAX_COMMAND_BYTES.saturating_sub(*used);
        if room == 0 {
            return Err(protocol("responses exceed 48MiB"));
        }
        let resp = self.read_response_budget(room)?;
        *used = used
            .checked_add(resp.len())
            .ok_or_else(|| protocol("responses exceed 48MiB"))?;
        if *used > MAX_COMMAND_BYTES {
            return Err(protocol("responses exceed 48MiB"));
        }
        Ok(resp)
    }

    /// Draft bytes. Not a command: written only after a `+` continuation.
    fn write_literal(&mut self, bytes: &[u8]) -> Result<(), Error> {
        self.stream.write_all(bytes)?;
        self.stream.write_all(b"\r\n")?;
        self.stream.flush()?;
        Ok(())
    }

    fn apply_mailbox_op(&mut self, op: MailboxOp, ok: bool) {
        match op {
            MailboxOp::Keep => {}
            MailboxOp::Select(name) => {
                self.mailbox = if ok {
                    MailboxState::Selected(name)
                } else {
                    MailboxState::None
                };
            }
            MailboxOp::Examine(name) => {
                self.mailbox = if ok {
                    MailboxState::Examined(name)
                } else {
                    MailboxState::None
                };
            }
            MailboxOp::Unselect => {
                if ok {
                    self.mailbox = MailboxState::None;
                }
            }
        }
    }

    /// Recover the stream. Fails if any byte past the last consumed response is already buffered.
    ///
    /// That is the STARTTLS injection guard: a server that appends bytes to the `STARTTLS` OK
    /// line (in the same read) must not have those bytes interpreted as a TLS handshake.
    pub fn into_inner(self) -> Result<S, Error> {
        if self.pos < self.buf.len() {
            return Err(protocol("unread bytes buffered"));
        }
        Ok(self.stream)
    }

    /// The only function that writes command bytes.
    ///
    /// `literal` is not written here. It is checked against a synchronizing `{n}` and, when the
    /// server answers `+`, sent by [`Self::write_literal`].
    fn write_command(
        &mut self,
        cmd: &str,
        literal: Option<&[u8]>,
    ) -> Result<(String, MailboxOp), Error> {
        if !is_printable_ascii(cmd) {
            return Err(invalid("command contains illegal bytes"));
        }
        if cmd.len() > MAX_COMMAND {
            return Err(invalid("command too long"));
        }
        let decision = command_allowed(cmd, &self.mailbox)?;
        if let Some(n) = decision.literal {
            match literal {
                Some(bytes) if bytes.len() == n => {}
                _ => return Err(invalid("synchronizing literal required")),
            }
        } else if literal.is_some() {
            return Err(invalid("literal not allowed"));
        }
        let tag = self.alloc_tag()?;
        let mut bytes = Vec::new();
        let tag_len = tag.len();
        let total = tag_len
            .checked_add(1)
            .and_then(|n| n.checked_add(cmd.len()))
            .and_then(|n| n.checked_add(2))
            .ok_or_else(|| invalid("command too long"))?;
        bytes
            .try_reserve(total)
            .map_err(|_| invalid("command too long"))?;
        bytes.extend_from_slice(tag.as_bytes());
        bytes.push(b' ');
        bytes.extend_from_slice(cmd.as_bytes());
        bytes.extend_from_slice(b"\r\n");
        self.stream.write_all(&bytes)?;
        self.stream.flush()?;
        Ok((tag, decision.op))
    }

    fn alloc_tag(&mut self) -> Result<String, Error> {
        let n = self.next_tag;
        self.next_tag = self
            .next_tag
            .checked_add(1)
            .ok_or_else(|| protocol("tag counter exhausted"))?;
        Ok(format!("a{n}"))
    }

    fn read_response(&mut self) -> Result<Vec<u8>, Error> {
        self.read_response_budget(MAX_RESPONSE)
    }

    /// Read one response, refusing to grow it past `budget` bytes.
    ///
    /// `budget` is the per-response cap (16 MiB) or whatever remains of the
    /// per-command cap, whichever is smaller.
    fn read_response_budget(&mut self, budget: usize) -> Result<Vec<u8>, Error> {
        let cap = budget.min(MAX_RESPONSE);
        let mut out = Vec::new();
        loop {
            let line = self.read_line()?;
            let lit = literal_len(&line)?;
            append_response(&mut out, line, cap)?;
            if let Some(n) = lit {
                if n > MAX_LITERAL {
                    return Err(protocol("literal exceeds 8MiB"));
                }
                ensure_response_budget(out.len(), n, cap)?;
                self.read_exact_append(&mut out, n)?;
                continue;
            }
            break;
        }
        Ok(out)
    }

    fn read_line(&mut self) -> Result<Vec<u8>, Error> {
        loop {
            if let Some(line) = self.take_line()? {
                return Ok(line);
            }
            let buffered = self.buf.len().saturating_sub(self.pos);
            let limit = self.pending_line_limit();
            if buffered >= limit {
                return Err(line_too_long(limit));
            }
            let mut tmp = [0u8; 1024];
            self.check_deadline()?;
            let n = self.stream.read(&mut tmp)?;
            if n == 0 {
                return Err(protocol("unexpected end of response"));
            }
            let got = tmp.get(..n).ok_or_else(|| protocol("read bounds"))?;
            self.buf
                .try_reserve(got.len())
                .map_err(|_| protocol("line too large"))?;
            self.buf.extend_from_slice(got);
        }
    }

    fn pending_line_limit(&self) -> usize {
        let available = self.buf.get(self.pos..).unwrap_or(b"");
        if allows_long_line(available) {
            MAX_RESPONSE
        } else {
            MAX_LINE
        }
    }

    fn take_line(&mut self) -> Result<Option<Vec<u8>>, Error> {
        if self.scan_from < self.pos {
            self.scan_from = self.pos;
        }
        let limit = self.pending_line_limit();
        if let Some(rel) = self.find_crlf_rel() {
            let end_rel = rel.checked_add(2).ok_or_else(|| protocol("line length"))?;
            if end_rel > limit {
                return Err(line_too_long(limit));
            }
            let end = self
                .pos
                .checked_add(end_rel)
                .ok_or_else(|| protocol("line length"))?;
            let line = self.take_bytes(end)?;
            return Ok(Some(line));
        }
        let available_len = self.buf.len().saturating_sub(self.pos);
        // Leave a trailing CR unscanned so the next byte can complete CRLF.
        self.scan_from = if self.buf.last() == Some(&b'\r') && self.buf.len() > self.pos {
            self.buf.len().saturating_sub(1)
        } else {
            self.buf.len()
        };
        if available_len >= limit {
            return Err(line_too_long(limit));
        }
        Ok(None)
    }

    /// Index of `\r\n` relative to `pos`, scanning only from `scan_from`.
    fn find_crlf_rel(&self) -> Option<usize> {
        let mut search_at = self.scan_from.max(self.pos);
        if search_at > self.pos && self.buf.get(search_at.saturating_sub(1)) == Some(&b'\r') {
            search_at = search_at.saturating_sub(1);
        }
        let hay = self.buf.get(search_at..)?;
        let rel = hay.windows(2).position(|pair| pair == b"\r\n")?;
        let abs = search_at.checked_add(rel)?;
        abs.checked_sub(self.pos)
    }

    /// Take `buf[pos..end]` and advance past it. Moves the bytes when `pos` is 0.
    fn take_bytes(&mut self, end: usize) -> Result<Vec<u8>, Error> {
        if end > self.buf.len() || end < self.pos {
            return Err(protocol("buffer bounds"));
        }
        let line = if self.pos == 0 {
            let mut rest = self.buf.split_off(end);
            std::mem::swap(&mut rest, &mut self.buf);
            self.pos = 0;
            self.scan_from = 0;
            rest
        } else {
            let line = self
                .buf
                .get(self.pos..end)
                .ok_or_else(|| protocol("buffer bounds"))?
                .to_vec();
            self.pos = end;
            self.compact();
            line
        };
        Ok(line)
    }

    fn read_exact_append(&mut self, out: &mut Vec<u8>, mut left: usize) -> Result<(), Error> {
        while left > 0 {
            let buffered = self.buf.len().saturating_sub(self.pos);
            if buffered > 0 {
                let take = buffered.min(left);
                let start = self.pos;
                let end = start
                    .checked_add(take)
                    .ok_or_else(|| protocol("offset overflow"))?;
                let slice = self
                    .buf
                    .get(start..end)
                    .ok_or_else(|| protocol("buffer bounds"))?;
                out.try_reserve(take)
                    .map_err(|_| protocol("response too large"))?;
                out.extend_from_slice(slice);
                self.pos = end;
                left -= take;
                self.compact();
                continue;
            }
            let chunk = left.min(8192);
            let mut tmp = vec![0u8; chunk];
            let mut filled = 0usize;
            while filled < chunk {
                let dest = tmp
                    .get_mut(filled..)
                    .ok_or_else(|| protocol("read bounds"))?;
                self.check_deadline()?;
                let n = self.stream.read(dest)?;
                if n == 0 {
                    return Err(protocol("unexpected end of literal"));
                }
                filled = filled
                    .checked_add(n)
                    .ok_or_else(|| protocol("offset overflow"))?;
            }
            let got = tmp.get(..filled).ok_or_else(|| protocol("read bounds"))?;
            out.try_reserve(got.len())
                .map_err(|_| protocol("response too large"))?;
            out.extend_from_slice(got);
            left -= filled;
        }
        Ok(())
    }

    fn compact(&mut self) {
        if self.pos == 0 {
            return;
        }
        if self.pos >= self.buf.len() {
            self.buf.clear();
            self.pos = 0;
            self.scan_from = 0;
            return;
        }
        if self.pos >= 4096 {
            let drop_n = self.pos;
            self.buf.drain(..drop_n);
            self.pos = 0;
            self.scan_from = self.scan_from.saturating_sub(drop_n);
        }
    }
}

/// A mailbox from `LIST`. `noselect` is set for `\Noselect` or `\NonExistent`.
#[derive(Debug, Clone, PartialEq)]
pub struct Mailbox {
    pub name: String,
    pub noselect: bool,
}

/// One `FETCH` result. `data` is the `BODY[...]` value, never decoded further.
#[derive(Debug, Clone, PartialEq)]
pub struct Fetched {
    pub uid: u32,
    pub flags: Vec<String>,
    pub size: Option<u64>,
    pub data: Option<Vec<u8>>,
}

/// Flags `UID STORE` may add or remove. There is no `\Deleted` variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Flag {
    Seen,
    Flagged,
}

/// `UID SEARCH` criteria. Dates are `YYYY-MM-DD`. `max_uid` keeps UIDs `<= max_uid`.
/// `message_id` is sent as `HEADER MESSAGE-ID`.
#[derive(Debug, Clone, Default)]
pub struct Search {
    pub from: Option<String>,
    pub subject: Option<String>,
    pub text: Option<String>,
    pub since: Option<String>,
    pub before: Option<String>,
    pub unseen: bool,
    pub max_uid: Option<u32>,
    pub message_id: Option<String>,
}

/// A logged-in IMAP session.
pub struct Session<S> {
    conn: Conn<S>,
}

impl<S: Read + Write> Session<S> {
    pub fn login(mut conn: Conn<S>, user: &str, password: &str) -> Result<Self, Error> {
        let quoted_user = quote_arg(user)?;
        let quoted_password = quote_arg(password)?;
        let cmd = format!("LOGIN {quoted_user} {quoted_password}");
        conn.command(&cmd)?;
        Ok(Session { conn })
    }

    pub fn list_mailboxes(&mut self) -> Result<Vec<Mailbox>, Error> {
        let responses = self.conn.command("LIST \"\" \"*\"")?;
        let mut out = Vec::new();
        for resp in &responses {
            if kind_of(resp) != Kind::List {
                continue;
            }
            if let Some(mailbox) = parse_list(resp)? {
                out.push(mailbox);
            }
        }
        Ok(out)
    }

    pub fn examine(&mut self, mailbox: &str) -> Result<(), Error> {
        let quoted = quote_arg(mailbox)?;
        let cmd = format!("EXAMINE {quoted}");
        self.conn.command(&cmd)?;
        Ok(())
    }

    /// Select `mailbox` read-write. Replaces any mailbox already selected or examined.
    pub fn select(&mut self, mailbox: &str) -> Result<(), Error> {
        let quoted = quote_arg(mailbox)?;
        let cmd = format!("SELECT {quoted}");
        self.conn.command(&cmd)?;
        Ok(())
    }

    pub fn uid_search(&mut self, query: &Search) -> Result<Vec<u32>, Error> {
        let criteria = search_criteria(query)?;
        let cmd = format!("UID SEARCH {criteria}");
        let responses = self.conn.command(&cmd)?;
        let mut uids = Vec::new();
        for resp in &responses {
            if kind_of(resp) != Kind::Search {
                continue;
            }
            uids.extend(parse_search(resp)?);
        }
        uids.sort_unstable();
        Ok(uids)
    }

    pub fn fetch_headers(&mut self, uids: &[u32]) -> Result<Vec<Fetched>, Error> {
        if uids.is_empty() {
            return Ok(Vec::new());
        }
        let set = format_uid_set(uids)?;
        let cmd = format!(
            "UID FETCH {set} (UID FLAGS RFC822.SIZE BODY.PEEK[HEADER.FIELDS (DATE FROM TO CC SUBJECT MESSAGE-ID REPLY-TO AUTHENTICATION-RESULTS RECEIVED X-PM-SPAM-ACTION X-PM-SPAMSCORE X-PM-ORIGIN)]<0.{HEADER_PEEK_BYTES}>)"
        );
        self.collect_fetches(&cmd)
    }

    pub fn fetch_message(&mut self, uid: u32, max_bytes: u32) -> Result<Option<Fetched>, Error> {
        if uid == 0 {
            return Err(invalid("uid must be non-zero"));
        }
        let cmd = format!("UID FETCH {uid} (UID FLAGS RFC822.SIZE BODY.PEEK[]<0.{max_bytes}>)");
        let fetched = self.collect_fetches(&cmd)?;
        Ok(fetched.into_iter().find(|item| item.uid == uid))
    }

    /// `UID MOVE`. Pairs are `(old, new)` from `COPYUID`, or empty when that code is absent.
    pub fn uid_move(&mut self, uids: &[u32], dest: &str) -> Result<Vec<(u32, u32)>, Error> {
        self.uid_relocate("MOVE", uids, dest)
    }

    /// `UID COPY`. Pairs are `(old, new)` from `COPYUID`, or empty when that code is absent.
    pub fn uid_copy(&mut self, uids: &[u32], dest: &str) -> Result<Vec<(u32, u32)>, Error> {
        self.uid_relocate("COPY", uids, dest)
    }

    /// `UID STORE` `+FLAGS.SILENT` or `-FLAGS.SILENT` for [`Flag::Seen`] and [`Flag::Flagged`].
    pub fn uid_store_flags(
        &mut self,
        uids: &[u32],
        add: bool,
        flags: &[Flag],
    ) -> Result<(), Error> {
        let set = format_uid_set_max(uids, MAX_WRITE_UIDS)?;
        let listed = format_store_flags(flags)?;
        let op = if add {
            "+FLAGS.SILENT"
        } else {
            "-FLAGS.SILENT"
        };
        let cmd = format!("UID STORE {set} {op} {listed}");
        self.conn.command(&cmd)?;
        Ok(())
    }

    /// Drop the label on `uids`. Selects `label_mailbox`, marks `\Deleted`, `UID EXPUNGE`s
    /// those UIDs, then `UNSELECT`. The name must start with `Labels/`.
    ///
    /// This is the only session method that sends `\Deleted` or `EXPUNGE`. On a label mailbox
    /// Bridge removes the label and leaves the message in its folder.
    pub fn remove_label(&mut self, label_mailbox: &str, uids: &[u32]) -> Result<(), Error> {
        let Some(rest) = label_mailbox.strip_prefix("Labels/") else {
            return Err(invalid("label mailbox must start with Labels/"));
        };
        if rest.is_empty() || rest.split('/').any(|segment| segment.is_empty()) {
            return Err(invalid("label mailbox must start with Labels/"));
        }
        let set = format_uid_set_max(uids, MAX_WRITE_UIDS)?;
        self.select(label_mailbox)?;
        let store = format!("UID STORE {set} +FLAGS.SILENT (\\Deleted)");
        if let Err(err) = self.conn.command(&store) {
            let _ = self.conn.command("UNSELECT");
            return Err(err);
        }
        let expunged = self.conn.command(&format!("UID EXPUNGE {set}"));
        let unselected = self.conn.command("UNSELECT");
        expunged?;
        unselected?;
        Ok(())
    }

    /// `CREATE` a mailbox under `Folders/` or `Labels/`.
    pub fn create(&mut self, mailbox: &str) -> Result<(), Error> {
        validate_create_name(mailbox)?;
        let quoted = quote_arg(mailbox)?;
        self.conn.command(&format!("CREATE {quoted}"))?;
        Ok(())
    }

    /// `APPEND` to `Drafts` with `(\Draft \Seen)`. Waits for `+`, then sends `message`.
    ///
    /// Returns the UID from `APPENDUID` when Bridge sends one. The message is capped at 2 MiB.
    /// Bridge drops `In-Reply-To` and `References` on `APPEND`; threading is not preserved.
    pub fn append_draft(&mut self, message: &[u8]) -> Result<Option<u32>, Error> {
        if message.len() > MAX_APPEND_BYTES {
            return Err(invalid("draft exceeds 2MiB"));
        }
        let cmd = format!("APPEND \"Drafts\" (\\Draft \\Seen) {{{}}}", message.len());
        let (untagged, tagged) = self.conn.transact(&cmd, Some(message))?;
        append_uid(&untagged, &tagged)
    }

    /// Best effort. Errors, including a dropped connection, are ignored.
    pub fn logout(mut self) {
        let _ = self.conn.command("LOGOUT");
    }

    fn collect_fetches(&mut self, cmd: &str) -> Result<Vec<Fetched>, Error> {
        let responses = self.conn.command(cmd)?;
        let mut out = Vec::new();
        for resp in responses {
            if kind_of(&resp) != Kind::Fetch {
                continue;
            }
            if let Some(fetched) = parse_fetch(&resp)? {
                out.push(fetched);
            }
        }
        Ok(out)
    }

    fn uid_relocate(
        &mut self,
        verb: &str,
        uids: &[u32],
        dest: &str,
    ) -> Result<Vec<(u32, u32)>, Error> {
        if dest.is_empty() {
            return Err(invalid("empty mailbox"));
        }
        let set = format_uid_set_max(uids, MAX_WRITE_UIDS)?;
        let quoted = quote_arg(dest)?;
        let cmd = format!("UID {verb} {set} {quoted}");
        let (untagged, tagged) = self.conn.transact(&cmd, None)?;
        copyuid_pairs(&untagged, &tagged)
    }
}

fn is_printable_ascii(s: &str) -> bool {
    s.bytes().all(|b| matches!(b, 0x20..=0x7E))
}

fn refused() -> Error {
    invalid("command not allowed")
}

/// Allowlist. The verb is the first parsed atom, never a substring of a later argument.
fn command_allowed(cmd: &str, selected: &MailboxState) -> Result<Decision, Error> {
    let Some((verb, rest)) = take_atom(cmd) else {
        return Err(refused());
    };
    if verb.eq_ignore_ascii_case("UID") {
        let Some((second, rest)) = take_atom(rest) else {
            return Err(refused());
        };
        if second.eq_ignore_ascii_case("SEARCH") || second.eq_ignore_ascii_case("FETCH") {
            return Ok(Decision {
                op: MailboxOp::Keep,
                literal: None,
            });
        }
        if second.eq_ignore_ascii_case("STORE") {
            return authorize_uid_store(rest, selected);
        }
        if second.eq_ignore_ascii_case("COPY") || second.eq_ignore_ascii_case("MOVE") {
            return authorize_uid_copy_move(rest, selected);
        }
        if second.eq_ignore_ascii_case("EXPUNGE") {
            return authorize_uid_expunge(rest, selected);
        }
        return Err(refused());
    }
    if verb.eq_ignore_ascii_case("SELECT") {
        return authorize_select(rest, false);
    }
    if verb.eq_ignore_ascii_case("EXAMINE") {
        return authorize_select(rest, true);
    }
    if verb.eq_ignore_ascii_case("CREATE") {
        return authorize_create(rest);
    }
    if verb.eq_ignore_ascii_case("UNSELECT") {
        return authorize_unselect(rest);
    }
    if verb.eq_ignore_ascii_case("APPEND") {
        return authorize_append(rest);
    }
    const SIMPLE: &[&str] = &["CAPABILITY", "STARTTLS", "LOGIN", "LIST", "NOOP", "LOGOUT"];
    if SIMPLE.iter().any(|name| verb.eq_ignore_ascii_case(name)) {
        return Ok(Decision {
            op: MailboxOp::Keep,
            literal: None,
        });
    }
    Err(refused())
}

fn authorize_select(rest: &str, examine: bool) -> Result<Decision, Error> {
    let name = one_mailbox(rest)?;
    let op = if examine {
        MailboxOp::Examine(name)
    } else {
        MailboxOp::Select(name)
    };
    Ok(Decision { op, literal: None })
}

fn authorize_create(rest: &str) -> Result<Decision, Error> {
    let name = one_mailbox(rest)?;
    validate_create_name(&name)?;
    Ok(Decision {
        op: MailboxOp::Keep,
        literal: None,
    })
}

fn authorize_unselect(rest: &str) -> Result<Decision, Error> {
    let mut cur = Cur::new(rest);
    if !cur.finished() {
        return Err(refused());
    }
    Ok(Decision {
        op: MailboxOp::Unselect,
        literal: None,
    })
}

fn authorize_uid_store(rest: &str, selected: &MailboxState) -> Result<Decision, Error> {
    let MailboxState::Selected(mailbox) = selected else {
        return Err(refused());
    };
    let mut cur = Cur::new(rest);
    let set = cur.atom().ok_or_else(refused)?;
    if !valid_uid_set(set) {
        return Err(refused());
    }
    let op = cur.atom().ok_or_else(refused)?;
    let add = if op.eq_ignore_ascii_case("+FLAGS.SILENT") {
        true
    } else if op.eq_ignore_ascii_case("-FLAGS.SILENT") {
        false
    } else {
        return Err(refused());
    };
    let flags = cur.flag_list()?;
    if !cur.finished() || !store_flags_allowed(&flags, add, mailbox) {
        return Err(refused());
    }
    Ok(Decision {
        op: MailboxOp::Keep,
        literal: None,
    })
}

fn authorize_uid_copy_move(rest: &str, selected: &MailboxState) -> Result<Decision, Error> {
    if !matches!(selected, MailboxState::Selected(_)) {
        return Err(refused());
    }
    let mut cur = Cur::new(rest);
    let set = cur.atom().ok_or_else(refused)?;
    if !valid_uid_set(set) {
        return Err(refused());
    }
    let dest = cur.mailbox().map_err(|_| refused())?;
    if dest.is_empty() || !cur.finished() {
        return Err(refused());
    }
    Ok(Decision {
        op: MailboxOp::Keep,
        literal: None,
    })
}

fn authorize_uid_expunge(rest: &str, selected: &MailboxState) -> Result<Decision, Error> {
    let MailboxState::Selected(name) = selected else {
        return Err(refused());
    };
    if !name.starts_with("Labels/") {
        return Err(refused());
    }
    let mut cur = Cur::new(rest);
    let set = cur.atom().ok_or_else(refused)?;
    if !valid_uid_set(set) || !cur.finished() {
        return Err(refused());
    }
    Ok(Decision {
        op: MailboxOp::Keep,
        literal: None,
    })
}

fn authorize_append(rest: &str) -> Result<Decision, Error> {
    let mut cur = Cur::new(rest);
    let mailbox = cur.mailbox().map_err(|_| refused())?;
    if mailbox != "Drafts" {
        return Err(refused());
    }
    cur.skip_ws();
    if cur.rest().starts_with('(') {
        let _flags = cur.flag_list()?;
    }
    cur.skip_ws();
    if cur.rest().starts_with('"') {
        let _date = cur.quoted().map_err(|_| refused())?;
    }
    let literal = cur.atom().ok_or_else(refused)?;
    let Some(n) = sync_literal_len(literal) else {
        return Err(refused());
    };
    if !cur.finished() {
        return Err(refused());
    }
    Ok(Decision {
        op: MailboxOp::Keep,
        literal: Some(n),
    })
}

fn store_flags_allowed(flags: &[String], add: bool, mailbox: &str) -> bool {
    if flags.is_empty() {
        return false;
    }
    let mut deleted = false;
    for flag in flags {
        if flag.eq_ignore_ascii_case("\\Seen") || flag.eq_ignore_ascii_case("\\Flagged") {
            continue;
        }
        if flag.eq_ignore_ascii_case("\\Deleted") {
            deleted = true;
            continue;
        }
        return false;
    }
    !deleted || (add && mailbox.starts_with("Labels/"))
}

fn validate_create_name(name: &str) -> Result<(), Error> {
    let rest = if let Some(rest) = name.strip_prefix("Folders/") {
        rest
    } else if let Some(rest) = name.strip_prefix("Labels/") {
        rest
    } else {
        return Err(invalid("mailbox must start with Folders/ or Labels/"));
    };
    if rest.is_empty() {
        return Err(invalid("mailbox name has an empty segment"));
    }
    for segment in rest.split('/') {
        if segment.is_empty() {
            return Err(invalid("mailbox name has an empty segment"));
        }
        if segment.bytes().any(|b| b == b'*' || b == b'%') {
            return Err(invalid("mailbox name contains a wildcard"));
        }
        if !is_printable_ascii(segment) {
            return Err(invalid("argument contains illegal bytes"));
        }
    }
    Ok(())
}

fn one_mailbox(rest: &str) -> Result<String, Error> {
    let mut cur = Cur::new(rest);
    let name = cur.mailbox().map_err(|_| refused())?;
    if name.is_empty() || !cur.finished() {
        return Err(refused());
    }
    Ok(name)
}

fn take_atom(input: &str) -> Option<(&str, &str)> {
    let s = input.trim_start_matches(' ');
    if s.is_empty() {
        return None;
    }
    let bytes = s.as_bytes();
    if matches!(bytes.first(), Some(b'"' | b'(' | b')')) {
        return None;
    }
    let end = bytes.iter().position(|&b| b == b' ').unwrap_or(bytes.len());
    if end == 0 {
        return None;
    }
    Some((&s[..end], &s[end..]))
}

fn valid_uid_set(set: &str) -> bool {
    if set.is_empty() || set.len() > MAX_COMMAND {
        return false;
    }
    set.split(',').all(valid_uid_item)
}

fn valid_uid_item(item: &str) -> bool {
    match item.split_once(':') {
        Some((left, right)) => nz_u32(left) && nz_u32(right),
        None => nz_u32(item),
    }
}

fn nz_u32(s: &str) -> bool {
    if s.is_empty() || s.len() > 10 || !s.bytes().all(|b| b.is_ascii_digit()) || s.starts_with('0')
    {
        return false;
    }
    s.parse::<u32>().is_ok()
}

fn sync_literal_len(token: &str) -> Option<usize> {
    let inner = token.strip_prefix('{')?.strip_suffix('}')?;
    if inner.is_empty() || !inner.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    if inner.len() > 1 && inner.starts_with('0') {
        return None;
    }
    let n: usize = inner.parse().ok()?;
    if n > MAX_APPEND_BYTES {
        return None;
    }
    Some(n)
}

fn format_store_flags(flags: &[Flag]) -> Result<String, Error> {
    if flags.is_empty() {
        return Err(invalid("empty flag list"));
    }
    let mut seen = false;
    let mut flagged = false;
    let mut parts = Vec::new();
    for flag in flags {
        let (already, name) = match flag {
            Flag::Seen => (&mut seen, "\\Seen"),
            Flag::Flagged => (&mut flagged, "\\Flagged"),
        };
        if *already {
            continue;
        }
        *already = true;
        parts.push(name);
    }
    Ok(format!("({})", parts.join(" ")))
}

struct Cur<'a> {
    s: &'a str,
    i: usize,
}

impl<'a> Cur<'a> {
    fn new(s: &'a str) -> Self {
        Self { s, i: 0 }
    }

    fn rest(&self) -> &'a str {
        self.s.get(self.i..).unwrap_or("")
    }

    fn skip_ws(&mut self) {
        while self.rest().starts_with(' ') {
            self.i = self.i.saturating_add(1);
        }
    }

    fn finished(&mut self) -> bool {
        self.skip_ws();
        self.rest().is_empty()
    }

    fn atom(&mut self) -> Option<&'a str> {
        self.skip_ws();
        let rest = self.rest();
        let bytes = rest.as_bytes();
        if bytes.is_empty() || matches!(bytes.first(), Some(b'"' | b'(' | b')')) {
            return None;
        }
        let end = bytes
            .iter()
            .position(|&b| b == b' ' || b == b')')
            .unwrap_or(bytes.len());
        if end == 0 {
            return None;
        }
        let atom = rest.get(..end)?;
        self.i = self.i.saturating_add(end);
        Some(atom)
    }

    fn mailbox(&mut self) -> Result<String, ()> {
        self.skip_ws();
        if self.rest().starts_with('"') {
            self.quoted()
        } else {
            self.atom().map(str::to_string).ok_or(())
        }
    }

    fn quoted(&mut self) -> Result<String, ()> {
        self.skip_ws();
        let bytes = self.s.as_bytes();
        if bytes.get(self.i) != Some(&b'"') {
            return Err(());
        }
        self.i = self.i.saturating_add(1);
        let mut out = String::new();
        loop {
            let Some(&c) = bytes.get(self.i) else {
                return Err(());
            };
            self.i = self.i.saturating_add(1);
            if c == b'"' {
                return Ok(out);
            }
            if c == b'\\' {
                let Some(&escaped) = bytes.get(self.i) else {
                    return Err(());
                };
                if escaped != b'\\' && escaped != b'"' {
                    return Err(());
                }
                self.i = self.i.saturating_add(1);
                out.push(char::from(escaped));
                continue;
            }
            out.push(char::from(c));
        }
    }

    fn flag_list(&mut self) -> Result<Vec<String>, Error> {
        self.skip_ws();
        if self.rest().starts_with('(') {
            self.i = self.i.saturating_add(1);
            let mut flags = Vec::new();
            loop {
                self.skip_ws();
                if self.rest().starts_with(')') {
                    self.i = self.i.saturating_add(1);
                    break;
                }
                let atom = self.atom().ok_or_else(refused)?;
                flags.push(atom.to_string());
            }
            if flags.is_empty() {
                return Err(refused());
            }
            return Ok(flags);
        }
        let atom = self.atom().ok_or_else(refused)?;
        Ok(vec![atom.to_string()])
    }
}

enum TaggedOutcome {
    Ok,
    No(String),
}

fn tagged_outcome(tag: &str, resp: &[u8]) -> Result<TaggedOutcome, Error> {
    let (got, status, text) = tagged_parts(resp)?;
    if got != tag.as_bytes() {
        return Err(protocol("unexpected response tag"));
    }
    if status.eq_ignore_ascii_case(b"OK") {
        return Ok(TaggedOutcome::Ok);
    }
    if status.eq_ignore_ascii_case(b"NO") || status.eq_ignore_ascii_case(b"BAD") {
        let body = if text.is_empty() {
            String::from_utf8_lossy(status).into_owned()
        } else {
            text
        };
        return Ok(TaggedOutcome::No(body));
    }
    Err(protocol("unexpected tagged status"))
}

fn refuse_continuation(tag: &str, resp: &[u8]) -> Result<(Vec<Vec<u8>>, Vec<u8>), Error> {
    if resp.first() == Some(&b'*') || resp.first() == Some(&b'+') {
        return Err(protocol("expected continuation"));
    }
    match tagged_outcome(tag, resp)? {
        TaggedOutcome::No(body) => Err(Error::Server(body)),
        TaggedOutcome::Ok => Err(protocol("expected continuation")),
    }
}

fn quote_arg(s: &str) -> Result<String, Error> {
    if !is_printable_ascii(s) {
        return Err(invalid("argument contains illegal bytes"));
    }
    if s.len() > MAX_COMMAND {
        return Err(invalid("argument too long"));
    }
    let mut out = String::new();
    out.try_reserve(s.len().saturating_add(2))
        .map_err(|_| invalid("argument too long"))?;
    out.push('"');
    for b in s.bytes() {
        if b == b'\\' || b == b'"' {
            out.push('\\');
        }
        out.push(char::from(b));
    }
    out.push('"');
    Ok(out)
}

fn format_imap_date(s: &str) -> Result<String, Error> {
    let (year, month, day) = parse_ymd(s)?;
    let name = match month {
        1 => "Jan",
        2 => "Feb",
        3 => "Mar",
        4 => "Apr",
        5 => "May",
        6 => "Jun",
        7 => "Jul",
        8 => "Aug",
        9 => "Sep",
        10 => "Oct",
        11 => "Nov",
        12 => "Dec",
        _ => return Err(invalid("invalid date")),
    };
    Ok(format!("{day}-{name}-{year:04}"))
}

fn parse_ymd(s: &str) -> Result<(u32, u32, u32), Error> {
    let b = s.as_bytes();
    if b.len() != 10 || b.get(4) != Some(&b'-') || b.get(7) != Some(&b'-') {
        return Err(invalid("invalid date"));
    }
    let year = b
        .get(0..4)
        .ok_or_else(|| invalid("invalid date"))
        .and_then(|part| parse_u32_bytes(part).map_err(|_| invalid("invalid date")))?;
    let month = b
        .get(5..7)
        .ok_or_else(|| invalid("invalid date"))
        .and_then(|part| parse_u32_bytes(part).map_err(|_| invalid("invalid date")))?;
    let day = b
        .get(8..10)
        .ok_or_else(|| invalid("invalid date"))
        .and_then(|part| parse_u32_bytes(part).map_err(|_| invalid("invalid date")))?;
    if !valid_ymd(year, month, day) {
        return Err(invalid("invalid date"));
    }
    Ok((year, month, day))
}

fn valid_ymd(year: u32, month: u32, day: u32) -> bool {
    let max = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400)) => {
            29
        }
        2 => 28,
        _ => return false,
    };
    (1..=max).contains(&day)
}

fn search_criteria(query: &Search) -> Result<String, Error> {
    let mut parts = Vec::new();
    if let Some(max_uid) = query.max_uid {
        if max_uid == 0 {
            return Err(invalid("uid must be non-zero"));
        }
        parts.push(format!("UID 1:{max_uid}"));
    }
    if let Some(from) = &query.from {
        parts.push(format!("FROM {}", quote_arg(from)?));
    }
    if let Some(subject) = &query.subject {
        parts.push(format!("SUBJECT {}", quote_arg(subject)?));
    }
    if let Some(text) = &query.text {
        parts.push(format!("TEXT {}", quote_arg(text)?));
    }
    if let Some(message_id) = &query.message_id {
        parts.push(format!("HEADER MESSAGE-ID {}", quote_arg(message_id)?));
    }
    if let Some(since) = &query.since {
        parts.push(format!("SINCE {}", format_imap_date(since)?));
    }
    if let Some(before) = &query.before {
        parts.push(format!("BEFORE {}", format_imap_date(before)?));
    }
    if query.unseen {
        parts.push("UNSEEN".to_string());
    }
    if parts.is_empty() {
        parts.push("ALL".to_string());
    }
    Ok(parts.join(" "))
}

fn format_uid_set(uids: &[u32]) -> Result<String, Error> {
    format_uid_set_max(uids, MAX_FETCH_UIDS)
}

fn format_uid_set_max(uids: &[u32], max: usize) -> Result<String, Error> {
    if uids.is_empty() {
        return Err(invalid("empty uid set"));
    }
    if uids.len() > max {
        return Err(invalid("too many uids"));
    }
    let mut out = String::new();
    for (i, uid) in uids.iter().enumerate() {
        if *uid == 0 {
            return Err(invalid("uid must be non-zero"));
        }
        if i > 0 {
            out.push(',');
        }
        out.push_str(&uid.to_string());
    }
    Ok(out)
}

fn copyuid_pairs(untagged: &[Vec<u8>], tagged: &[u8]) -> Result<Vec<(u32, u32)>, Error> {
    if let Some(payload) = response_code_payload(tagged, b"COPYUID") {
        return parse_copyuid_payload(payload);
    }
    for line in untagged {
        if let Some(payload) = response_code_payload(line, b"COPYUID") {
            return parse_copyuid_payload(payload);
        }
    }
    Ok(Vec::new())
}

fn append_uid(untagged: &[Vec<u8>], tagged: &[u8]) -> Result<Option<u32>, Error> {
    if let Some(payload) = response_code_payload(tagged, b"APPENDUID") {
        return Ok(Some(parse_one_uid_code(payload)?));
    }
    for line in untagged {
        if let Some(payload) = response_code_payload(line, b"APPENDUID") {
            return Ok(Some(parse_one_uid_code(payload)?));
        }
    }
    Ok(None)
}

fn parse_copyuid_payload(payload: &[u8]) -> Result<Vec<(u32, u32)>, Error> {
    let fields = split_ws(payload);
    if fields.len() != 3 {
        return Err(protocol("bad copyuid"));
    }
    let validity = fields.first().ok_or_else(|| protocol("bad copyuid"))?;
    let source = fields.get(1).ok_or_else(|| protocol("bad copyuid"))?;
    let dest = fields.get(2).ok_or_else(|| protocol("bad copyuid"))?;
    let validity = parse_u32_bytes(validity)?;
    if validity == 0 {
        return Err(protocol("bad copyuid"));
    }
    let source_uids = expand_uid_set(source)?;
    let dest_uids = expand_uid_set(dest)?;
    if source_uids.len() != dest_uids.len() {
        return Err(protocol("copyuid length mismatch"));
    }
    Ok(source_uids.into_iter().zip(dest_uids).collect())
}

fn parse_one_uid_code(payload: &[u8]) -> Result<u32, Error> {
    let fields = split_ws(payload);
    if fields.len() != 2 {
        return Err(protocol("bad appenduid"));
    }
    let validity = fields.first().ok_or_else(|| protocol("bad appenduid"))?;
    let uid_set = fields.get(1).ok_or_else(|| protocol("bad appenduid"))?;
    let validity = parse_u32_bytes(validity)?;
    if validity == 0 {
        return Err(protocol("bad appenduid"));
    }
    let uids = expand_uid_set(uid_set)?;
    let Some(uid) = uids.first().copied() else {
        return Err(protocol("bad appenduid"));
    };
    if uids.len() != 1 {
        return Err(protocol("bad appenduid"));
    }
    Ok(uid)
}

fn expand_uid_set(set: &[u8]) -> Result<Vec<u32>, Error> {
    if set.is_empty() {
        return Err(protocol("empty uid set in response"));
    }
    let mut out = Vec::new();
    for part in set.split(|&b| b == b',') {
        if part.is_empty() || part.contains(&b'*') {
            return Err(protocol("bad uid set in response"));
        }
        let (lo, hi) = if let Some(colon) = part.iter().position(|&b| b == b':') {
            let left = part.get(..colon).unwrap_or(b"");
            let right = part.get(colon.saturating_add(1)..).unwrap_or(b"");
            if right.contains(&b':') {
                return Err(protocol("bad uid set in response"));
            }
            let a = parse_u32_bytes(left)?;
            let b = parse_u32_bytes(right)?;
            if a == 0 || b == 0 {
                return Err(protocol("bad uid set in response"));
            }
            if a <= b { (a, b) } else { (b, a) }
        } else {
            let n = parse_u32_bytes(part)?;
            if n == 0 {
                return Err(protocol("bad uid set in response"));
            }
            (n, n)
        };
        let count = u64::from(hi)
            .saturating_sub(u64::from(lo))
            .saturating_add(1);
        let room = MAX_COPYUID.saturating_sub(out.len());
        if count > u64::try_from(room).unwrap_or(u64::MAX) {
            return Err(protocol("copyuid set too large"));
        }
        let mut n = lo;
        loop {
            out.push(n);
            if n == hi {
                break;
            }
            n = n.saturating_add(1);
        }
    }
    if out.is_empty() {
        return Err(protocol("empty uid set in response"));
    }
    Ok(out)
}

fn split_ws(bytes: &[u8]) -> Vec<&[u8]> {
    bytes
        .split(|b| matches!(b, b' ' | b'\t'))
        .filter(|part| !part.is_empty())
        .collect()
}

fn response_code_payload<'a>(buf: &'a [u8], name: &[u8]) -> Option<&'a [u8]> {
    let mut i = 0usize;
    while i < buf.len() {
        if buf.get(i) != Some(&b'[') {
            i = i.saturating_add(1);
            continue;
        }
        let mut j = i.saturating_add(1);
        while matches!(buf.get(j), Some(b' ' | b'\t')) {
            j = j.saturating_add(1);
        }
        let tail = buf.get(j..)?;
        let Some(head) = tail.get(..name.len()) else {
            i = i.saturating_add(1);
            continue;
        };
        if !head.eq_ignore_ascii_case(name) {
            i = i.saturating_add(1);
            continue;
        }
        let after = j.saturating_add(name.len());
        match buf.get(after) {
            Some(b' ' | b'\t') => {
                let mut k = after;
                while matches!(buf.get(k), Some(b' ' | b'\t')) {
                    k = k.saturating_add(1);
                }
                let rest = buf.get(k..)?;
                let end = rest.iter().position(|&b| b == b']')?;
                return rest.get(..end);
            }
            Some(b']') => return Some(b""),
            _ => i = i.saturating_add(1),
        }
    }
    None
}

fn ensure_response_budget(current: usize, add: usize, cap: usize) -> Result<(), Error> {
    let sum = current
        .checked_add(add)
        .ok_or_else(|| protocol("response too large"))?;
    if sum > cap {
        Err(response_cap_error(cap))
    } else {
        Ok(())
    }
}

fn response_cap_error(cap: usize) -> Error {
    if cap >= MAX_RESPONSE {
        protocol("response exceeds 16MiB")
    } else {
        protocol("responses exceed 48MiB")
    }
}

fn line_too_long(limit: usize) -> Error {
    if limit > MAX_LINE {
        protocol("line exceeds 16MiB")
    } else {
        protocol("line exceeds 64KiB")
    }
}

/// A `* SEARCH` line may run to the response cap. Every other line stays at 64 KiB.
fn allows_long_line(buf: &[u8]) -> bool {
    let mut i = 0usize;
    while matches!(buf.get(i), Some(b' ' | b'\t')) {
        i = i.saturating_add(1);
    }
    if buf.get(i) != Some(&b'*') {
        return false;
    }
    i = i.saturating_add(1);
    while matches!(buf.get(i), Some(b' ' | b'\t')) {
        i = i.saturating_add(1);
    }
    let Some(rest) = buf.get(i..) else {
        return false;
    };
    let word_len = rest
        .iter()
        .position(|b| matches!(b, b' ' | b'\t' | b'\r' | b'\n' | b'('))
        .unwrap_or(rest.len());
    let Some(word) = rest.get(..word_len) else {
        return false;
    };
    word.eq_ignore_ascii_case(b"SEARCH")
}

/// Append `line` to a response. The first chunk is moved so a long SEARCH line is not copied.
fn append_response(out: &mut Vec<u8>, line: Vec<u8>, cap: usize) -> Result<(), Error> {
    ensure_response_budget(out.len(), line.len(), cap)?;
    if out.is_empty() {
        *out = line;
        return Ok(());
    }
    out.try_reserve(line.len())
        .map_err(|_| response_cap_error(cap))?;
    out.extend_from_slice(&line);
    Ok(())
}

fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|pair| pair == b"\r\n")
}

fn literal_len(line: &[u8]) -> Result<Option<usize>, Error> {
    let body = line.strip_suffix(b"\r\n").unwrap_or(line);
    if !body.ends_with(b"}") {
        return Ok(None);
    }
    let close = body.len().saturating_sub(1);
    let Some(open) = body
        .get(..close)
        .and_then(|prefix| prefix.iter().rposition(|&b| b == b'{'))
    else {
        return Ok(None);
    };
    let mut inner = body.get(open.saturating_add(1)..close).unwrap_or(b"");
    if inner.last() == Some(&b'+') {
        inner = inner.get(..inner.len().saturating_sub(1)).unwrap_or(b"");
    }
    if inner.is_empty() || !inner.iter().all(u8::is_ascii_digit) {
        return Ok(None);
    }
    let n_u64 = parse_u64_bytes(inner).ok_or_else(|| protocol("literal length overflow"))?;
    let n = usize::try_from(n_u64).map_err(|_| protocol("literal too large"))?;
    Ok(Some(n))
}

fn is_ok_greeting(resp: &[u8]) -> bool {
    let Some(rest) = resp.strip_prefix(b"*") else {
        return false;
    };
    let Some(rest) = rest.strip_prefix(b" ") else {
        return false;
    };
    let Some(rest) = strip_prefix_ci(rest, b"OK") else {
        return false;
    };
    matches!(rest.first(), None | Some(b' ' | b'\r' | b'['))
}

fn strip_prefix_ci<'a>(buf: &'a [u8], pat: &[u8]) -> Option<&'a [u8]> {
    let prefix = buf.get(..pat.len())?;
    if prefix.eq_ignore_ascii_case(pat) {
        buf.get(pat.len()..)
    } else {
        None
    }
}

fn tagged_parts(resp: &[u8]) -> Result<(&[u8], &[u8], String), Error> {
    let line = match find_crlf(resp) {
        Some(i) => resp.get(..i).unwrap_or(resp),
        None => resp,
    };
    let mut i = skip_ws_idx(line, 0);
    let tag_start = i;
    i = skip_token(line, i);
    if i == tag_start {
        return Err(protocol("missing tag"));
    }
    let tag = line.get(tag_start..i).unwrap_or(b"");
    i = skip_ws_idx(line, i);
    let status_start = i;
    i = skip_token(line, i);
    if i == status_start {
        return Err(protocol("missing status"));
    }
    let status = line.get(status_start..i).unwrap_or(b"");
    i = skip_ws_idx(line, i);
    let text = truncate_bytes_as_text(line.get(i..).unwrap_or(b""), MAX_SERVER_CHARS);
    Ok((tag, status, text))
}

fn skip_ws_idx(buf: &[u8], mut i: usize) -> usize {
    while matches!(buf.get(i), Some(b' ' | b'\t')) {
        i = i.saturating_add(1);
    }
    i
}

fn skip_token(buf: &[u8], mut i: usize) -> usize {
    while let Some(b) = buf.get(i) {
        if matches!(b, b' ' | b'\t') {
            break;
        }
        i = i.saturating_add(1);
    }
    i
}

fn truncate_bytes_as_text(bytes: &[u8], max_chars: usize) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut count = 0usize;
    for (idx, _) in text.char_indices() {
        if count == max_chars {
            return text.get(..idx).unwrap_or("").to_string();
        }
        count = count.saturating_add(1);
    }
    text.into_owned()
}

fn parse_u32_bytes(bytes: &[u8]) -> Result<u32, Error> {
    if bytes.is_empty() {
        return Err(protocol("empty number"));
    }
    let mut n: u32 = 0;
    for &c in bytes {
        if !c.is_ascii_digit() {
            return Err(protocol("bad number"));
        }
        let digit = u32::from(c - b'0');
        n = n
            .checked_mul(10)
            .and_then(|v| v.checked_add(digit))
            .ok_or_else(|| protocol("number overflow"))?;
    }
    Ok(n)
}

fn parse_u64_bytes(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    let mut n: u64 = 0;
    for &c in bytes {
        if !c.is_ascii_digit() {
            return None;
        }
        let digit = u64::from(c - b'0');
        n = n.checked_mul(10)?.checked_add(digit)?;
    }
    Some(n)
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Fetch,
    List,
    Search,
    Other,
}

fn kind_of(buf: &[u8]) -> Kind {
    if after_star_word(buf, b"LIST").is_ok() {
        Kind::List
    } else if after_star_word(buf, b"SEARCH").is_ok() {
        Kind::Search
    } else if is_fetch_response(buf) {
        Kind::Fetch
    } else {
        Kind::Other
    }
}

fn after_star_word<'a>(buf: &'a [u8], word: &[u8]) -> Result<&'a [u8], Error> {
    let mut i = skip_ws_idx(buf, 0);
    if buf.get(i) != Some(&b'*') {
        return Err(protocol("expected untagged"));
    }
    i = i.saturating_add(1);
    i = skip_ws_idx(buf, i);
    let start = i;
    while let Some(b) = buf.get(i) {
        if matches!(b, b' ' | b'\t' | b'\r' | b'\n' | b'(') {
            break;
        }
        i = i.saturating_add(1);
    }
    let got = buf.get(start..i).unwrap_or(b"");
    if got.is_empty() || !got.eq_ignore_ascii_case(word) {
        return Err(protocol("unexpected untagged"));
    }
    Ok(buf.get(i..).unwrap_or(b""))
}

fn is_fetch_response(buf: &[u8]) -> bool {
    let words = first_words(buf, 3);
    match (words.first(), words.get(2)) {
        (Some(star), Some(verb)) => {
            star.eq_ignore_ascii_case(b"*") && verb.eq_ignore_ascii_case(b"FETCH")
        }
        _ => false,
    }
}

fn first_words(buf: &[u8], max: usize) -> Vec<&[u8]> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while out.len() < max {
        while matches!(buf.get(i), Some(b' ' | b'\t')) {
            i = match i.checked_add(1) {
                Some(n) => n,
                None => return out,
            };
        }
        match buf.get(i) {
            None | Some(b'\r' | b'\n') => break,
            Some(_) => {}
        }
        let start = i;
        loop {
            match buf.get(i) {
                Some(b' ' | b'\t' | b'\r' | b'\n') | None => break,
                Some(_) => {
                    i = match i.checked_add(1) {
                        Some(n) => n,
                        None => return out,
                    };
                }
            }
        }
        if i == start {
            break;
        }
        if let Some(word) = buf.get(start..i) {
            out.push(word);
        }
    }
    out
}

enum Value {
    Nil,
    Bytes(Vec<u8>),
    List(Vec<Value>),
}

struct Parser<'a> {
    data: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, i: 0 }
    }

    fn peek(&self) -> Option<u8> {
        self.data.get(self.i).copied()
    }

    fn bump(&mut self) -> Result<u8, Error> {
        let b = self.peek().ok_or_else(|| protocol("truncated"))?;
        self.i = self
            .i
            .checked_add(1)
            .ok_or_else(|| protocol("offset overflow"))?;
        Ok(b)
    }

    fn skip_ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.i = self.i.saturating_add(1);
        }
    }

    fn parse_value(&mut self, depth: usize) -> Result<Value, Error> {
        self.skip_ws();
        match self.peek() {
            Some(b'(') => self.parse_list(depth),
            Some(b'"') => self.parse_quoted(),
            Some(b'{') => self.parse_literal(),
            Some(b')' | b'\r' | b'\n') | None => Err(protocol("expected value")),
            Some(_) => self.parse_atom(),
        }
    }

    fn parse_list(&mut self, depth: usize) -> Result<Value, Error> {
        let depth = depth
            .checked_add(1)
            .ok_or_else(|| protocol("list too deep"))?;
        if depth > MAX_DEPTH {
            return Err(protocol("list too deep"));
        }
        self.bump()?;
        let mut items = Vec::new();
        loop {
            self.skip_ws();
            match self.peek() {
                Some(b')') => {
                    self.bump()?;
                    return Ok(Value::List(items));
                }
                None => return Err(protocol("unclosed list")),
                Some(_) => {
                    if items.len() >= MAX_LIST_ITEMS {
                        return Err(protocol("list too long"));
                    }
                    items.push(self.parse_value(depth)?);
                }
            }
        }
    }

    fn parse_quoted(&mut self) -> Result<Value, Error> {
        self.bump()?;
        let mut out = Vec::new();
        loop {
            let b = self.bump()?;
            match b {
                b'"' => return Ok(Value::Bytes(out)),
                b'\\' => {
                    let escaped = self.bump()?;
                    if escaped == 0 || escaped == b'\r' || escaped == b'\n' {
                        return Err(protocol("illegal escape"));
                    }
                    out.push(escaped);
                }
                0 | b'\r' | b'\n' => return Err(protocol("illegal quote byte")),
                _ => out.push(b),
            }
            if out.len() > MAX_RESPONSE {
                return Err(protocol("quoted too long"));
            }
        }
    }

    fn parse_literal(&mut self) -> Result<Value, Error> {
        self.bump()?;
        let start = self.i;
        while matches!(self.peek(), Some(b) if b.is_ascii_digit()) {
            self.bump()?;
        }
        if self.i == start {
            return Err(protocol("bad literal"));
        }
        let digits = self
            .data
            .get(start..self.i)
            .ok_or_else(|| protocol("literal bounds"))?;
        if self.peek() == Some(b'+') {
            self.bump()?;
        }
        if self.peek() != Some(b'}') {
            return Err(protocol("bad literal"));
        }
        self.bump()?;
        if self.peek() != Some(b'\r') || self.data.get(self.i.saturating_add(1)) != Some(&b'\n') {
            return Err(protocol("literal missing CRLF"));
        }
        self.bump()?;
        self.bump()?;
        let n_u64 = parse_u64_bytes(digits).ok_or_else(|| protocol("literal length overflow"))?;
        let n = usize::try_from(n_u64).map_err(|_| protocol("literal too large"))?;
        if n > MAX_LITERAL {
            return Err(protocol("literal exceeds 8MiB"));
        }
        let end = self
            .i
            .checked_add(n)
            .ok_or_else(|| protocol("literal bounds"))?;
        if end > self.data.len() {
            return Err(protocol("truncated literal"));
        }
        let bytes = self
            .data
            .get(self.i..end)
            .ok_or_else(|| protocol("literal bounds"))?
            .to_vec();
        self.i = end;
        Ok(Value::Bytes(bytes))
    }

    fn parse_atom(&mut self) -> Result<Value, Error> {
        let start = self.i;
        let mut brackets: usize = 0;
        let mut angle = false;
        while let Some(b) = self.peek() {
            if angle {
                self.bump()?;
                if b == b'>' {
                    // The '>' is part of the atom. Clear the flag so a
                    // closed `<...>` is not reported as unclosed.
                    angle = false;
                    break;
                }
                continue;
            }
            if brackets == 0 && is_atom_end(b) {
                break;
            }
            self.bump()?;
            if b == b'[' {
                brackets = brackets.saturating_add(1);
                if brackets > MAX_DEPTH {
                    return Err(protocol("bracket depth"));
                }
            } else if b == b']' && brackets > 0 {
                brackets -= 1;
                if brackets == 0 {
                    if self.peek() == Some(b'<') {
                        self.bump()?;
                        angle = true;
                    } else {
                        break;
                    }
                }
            }
        }
        if angle || brackets != 0 {
            return Err(protocol("unclosed section"));
        }
        if self.i == start {
            return Err(protocol("empty token"));
        }
        let atom = self
            .data
            .get(start..self.i)
            .ok_or_else(|| protocol("atom bounds"))?;
        if atom.eq_ignore_ascii_case(b"NIL") {
            Ok(Value::Nil)
        } else {
            Ok(Value::Bytes(atom.to_vec()))
        }
    }
}

fn is_atom_end(b: u8) -> bool {
    matches!(
        b,
        b' ' | b'\t' | b'(' | b')' | b'\r' | b'\n' | b'{' | b'"' | b']'
    )
}

fn parse_fetch(buf: &[u8]) -> Result<Option<Fetched>, Error> {
    let mut parser = Parser::new(buf);
    parser.skip_ws();
    if parser.peek() != Some(b'*') {
        return Err(protocol("not a fetch"));
    }
    parser.bump()?;
    let _seq = parser.parse_value(0)?;
    let verb = parser.parse_value(0)?;
    if !value_is_ci(&verb, b"FETCH") {
        return Err(protocol("not a fetch"));
    }
    let list = match parser.parse_value(0)? {
        Value::List(items) => items,
        _ => return Err(protocol("fetch list")),
    };
    interpret_fetch_items(list)
}

fn interpret_fetch_items(items: Vec<Value>) -> Result<Option<Fetched>, Error> {
    let mut uid = None;
    let mut flags = Vec::new();
    let mut size = None;
    let mut data = None;
    let mut items = items.into_iter();
    while let Some(key_val) = items.next() {
        let key = match key_val {
            Value::Bytes(bytes) => bytes,
            Value::Nil | Value::List(_) => return Err(protocol("fetch key")),
        };
        let Some(val) = items.next() else {
            return Err(protocol("fetch pair"));
        };
        if key_is(&key, b"UID") {
            uid = Some(value_u32(&val)?);
        } else if key_is(&key, b"FLAGS") {
            flags = value_flags(&val)?;
        } else if key_is(&key, b"RFC822.SIZE") {
            size = value_u64_opt(&val)?;
        } else if is_body_key(&key) {
            data = value_bytes_opt(val)?;
        }
    }
    // RFC 3501 allows an unsolicited FETCH (a flag change from another client) with no UID.
    let Some(uid) = uid else {
        return Ok(None);
    };
    Ok(Some(Fetched {
        uid,
        flags,
        size,
        data,
    }))
}

fn parse_list(buf: &[u8]) -> Result<Option<Mailbox>, Error> {
    let rest = after_star_word(buf, b"LIST")?;
    let mut parser = Parser::new(rest);
    let flags = parser.parse_value(0)?;
    let _delimiter = parser.parse_value(0)?;
    let name = parser.parse_value(0)?;
    let noselect = flags_noselect(&flags)?;
    match value_string(&name)? {
        Some(name) => Ok(Some(Mailbox { name, noselect })),
        None => Ok(None),
    }
}

fn parse_search(buf: &[u8]) -> Result<Vec<u32>, Error> {
    let rest = after_star_word(buf, b"SEARCH")?;
    if search_is_plain_numbers(rest) {
        parse_search_numbers(rest)
    } else {
        parse_search_values(rest)
    }
}

fn search_is_plain_numbers(rest: &[u8]) -> bool {
    rest.iter()
        .all(|b| matches!(b, b'0'..=b'9' | b' ' | b'\t' | b'\r' | b'\n'))
}

/// One pass, no per-UID allocation. A million-UID SEARCH line has to stay fast in debug.
fn parse_search_numbers(rest: &[u8]) -> Result<Vec<u32>, Error> {
    let mut uids = Vec::new();
    let mut i = 0usize;
    while i < rest.len() {
        match rest.get(i) {
            Some(b' ' | b'\t' | b'\r' | b'\n') => i = i.saturating_add(1),
            Some(b) if b.is_ascii_digit() => {
                let start = i;
                i = i.saturating_add(1);
                while matches!(rest.get(i), Some(b) if b.is_ascii_digit()) {
                    i = i.saturating_add(1);
                }
                let raw = rest.get(start..i).ok_or_else(|| protocol("search uid"))?;
                uids.push(parse_u32_bytes(raw)?);
            }
            _ => return Err(protocol("search uid")),
        }
    }
    Ok(uids)
}

fn parse_search_values(rest: &[u8]) -> Result<Vec<u32>, Error> {
    let mut parser = Parser::new(rest);
    let mut uids = Vec::new();
    loop {
        parser.skip_ws();
        match parser.peek() {
            None | Some(b'\r' | b'\n') => break,
            Some(_) => match parser.parse_value(0)? {
                Value::Bytes(raw) => uids.push(parse_u32_bytes(&raw)?),
                Value::Nil | Value::List(_) => return Err(protocol("search uid")),
            },
        }
    }
    Ok(uids)
}

fn value_is_ci(value: &Value, expected: &[u8]) -> bool {
    match value {
        Value::Bytes(bytes) => bytes.eq_ignore_ascii_case(expected),
        Value::Nil | Value::List(_) => false,
    }
}

fn key_is(key: &[u8], expected: &[u8]) -> bool {
    key.eq_ignore_ascii_case(expected)
}

fn is_body_key(key: &[u8]) -> bool {
    if starts_with_ci(key, b"BODYSTRUCTURE") {
        return false;
    }
    key_is(key, b"BODY") || starts_with_ci(key, b"BODY[") || starts_with_ci(key, b"BODY.PEEK[")
}

fn starts_with_ci(hay: &[u8], pat: &[u8]) -> bool {
    match hay.get(..pat.len()) {
        Some(prefix) => prefix.eq_ignore_ascii_case(pat),
        None => false,
    }
}

fn value_u32(value: &Value) -> Result<u32, Error> {
    match value {
        Value::Bytes(bytes) => parse_u32_bytes(bytes),
        Value::Nil | Value::List(_) => Err(protocol("expected number")),
    }
}

fn value_u64_opt(value: &Value) -> Result<Option<u64>, Error> {
    match value {
        Value::Nil => Ok(None),
        Value::Bytes(bytes) => {
            let n = parse_u64_bytes(bytes).ok_or_else(|| protocol("bad size"))?;
            Ok(Some(n))
        }
        Value::List(_) => Err(protocol("expected number")),
    }
}

fn value_bytes_opt(value: Value) -> Result<Option<Vec<u8>>, Error> {
    match value {
        Value::Nil => Ok(None),
        Value::Bytes(bytes) => Ok(Some(bytes)),
        Value::List(_) => Err(protocol("expected nstring")),
    }
}

fn value_flags(value: &Value) -> Result<Vec<String>, Error> {
    match value {
        Value::Nil => Ok(Vec::new()),
        Value::List(items) => {
            let mut flags = Vec::new();
            for item in items {
                match item {
                    Value::Bytes(bytes) => {
                        flags.push(String::from_utf8_lossy(bytes).into_owned());
                    }
                    Value::Nil | Value::List(_) => return Err(protocol("bad flag")),
                }
            }
            Ok(flags)
        }
        Value::Bytes(_) => Err(protocol("bad flags")),
    }
}

fn flags_noselect(value: &Value) -> Result<bool, Error> {
    match value {
        Value::Nil => Ok(false),
        Value::List(items) => {
            let mut noselect = false;
            for item in items {
                if let Value::Bytes(bytes) = item
                    && (bytes.eq_ignore_ascii_case(b"\\Noselect")
                        || bytes.eq_ignore_ascii_case(b"\\NonExistent"))
                {
                    noselect = true;
                }
            }
            Ok(noselect)
        }
        Value::Bytes(_) => Err(protocol("bad list flags")),
    }
}

fn value_string(value: &Value) -> Result<Option<String>, Error> {
    match value {
        Value::Nil => Ok(None),
        Value::Bytes(bytes) => Ok(Some(String::from_utf8_lossy(bytes).into_owned())),
        Value::List(_) => Err(protocol("expected string")),
    }
}

/// Exercise the parser on hostile bytes. Errors are fine; panics are not.
#[cfg(test)]
fn parse_fuzz(buf: &[u8]) -> Result<(), Error> {
    match kind_of(buf) {
        Kind::Fetch => {
            let _ = parse_fetch(buf)?;
        }
        Kind::List => {
            let _ = parse_list(buf)?;
        }
        Kind::Search => {
            let _ = parse_search(buf)?;
        }
        Kind::Other => {
            let mut parser = Parser::new(buf);
            for _ in 0..64 {
                parser.skip_ws();
                match parser.peek() {
                    None | Some(b'\r' | b'\n') => break,
                    Some(_) => {
                        let _ = parser.parse_value(0)?;
                    }
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    struct ScriptInner {
        inbound: Vec<u8>,
        pos: usize,
        written: Vec<u8>,
    }

    #[derive(Clone)]
    struct Script {
        inner: Arc<Mutex<ScriptInner>>,
    }

    impl Script {
        fn new(inbound: impl Into<Vec<u8>>) -> Self {
            Self {
                inner: Arc::new(Mutex::new(ScriptInner {
                    inbound: inbound.into(),
                    pos: 0,
                    written: Vec::new(),
                })),
            }
        }

        fn written(&self) -> Vec<u8> {
            match self.inner.lock() {
                Ok(guard) => guard.written.clone(),
                Err(poisoned) => poisoned.into_inner().written.clone(),
            }
        }
    }

    impl Read for Script {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let mut guard = self
                .inner
                .lock()
                .map_err(|_| std::io::Error::other("lock"))?;
            if guard.pos >= guard.inbound.len() {
                return Ok(0);
            }
            let available = guard.inbound.len() - guard.pos;
            let n = available.min(buf.len());
            let end = guard.pos + n;
            let src = guard
                .inbound
                .get(guard.pos..end)
                .ok_or_else(|| std::io::Error::other("script bounds"))?;
            let dest = buf
                .get_mut(..n)
                .ok_or_else(|| std::io::Error::other("script bounds"))?;
            dest.copy_from_slice(src);
            guard.pos = end;
            Ok(n)
        }
    }

    impl Write for Script {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let mut guard = self
                .inner
                .lock()
                .map_err(|_| std::io::Error::other("lock"))?;
            guard.written.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    fn written_str(script: &Script) -> String {
        String::from_utf8_lossy(&script.written()).into_owned()
    }

    fn force_err<T, E>(result: Result<T, E>) -> E {
        match result {
            Ok(_) => panic!("expected an error"),
            Err(err) => err,
        }
    }

    #[test]
    fn greeting_ok_preauth_and_bye() {
        let script = Script::new(b"* OK IMAP4rev1 ready\r\n".to_vec());
        let mut conn = Conn::new(script.clone());
        conn.read_greeting().unwrap();
        conn.into_inner().unwrap();

        let mut preauth = Conn::new(Script::new(b"* PREAUTH hi\r\n".to_vec()));
        assert!(matches!(preauth.read_greeting(), Err(Error::Protocol(_))));
        let mut bye = Conn::new(Script::new(b"* BYE go away\r\n".to_vec()));
        assert!(matches!(bye.read_greeting(), Err(Error::Protocol(_))));
        let mut lower = Conn::new(Script::new(b"* ok [CAPABILITY IMAP4rev1]\r\n".to_vec()));
        lower.read_greeting().unwrap();
    }

    #[test]
    fn into_inner_refuses_buffered_bytes() {
        let script = Script::new(b"* OK ready\r\nEXTRA".to_vec());
        let mut conn = Conn::new(script);
        conn.read_greeting().unwrap();
        let err = force_err(conn.into_inner());
        assert!(err.to_string().contains("unread bytes buffered"));
    }

    #[test]
    fn starttls_injection_is_refused() {
        let raw = b"* OK ready\r\na1 OK begin tls\r\nATTACK";
        let script = Script::new(raw.to_vec());
        let mut conn = Conn::new(script);
        conn.read_greeting().unwrap();
        conn.command("STARTTLS").unwrap();
        assert!(conn.into_inner().is_err());
    }

    #[test]
    fn into_inner_accepts_exact_response() {
        let script = Script::new(b"* OK ready\r\na1 OK done\r\n".to_vec());
        let mut conn = Conn::new(script.clone());
        conn.read_greeting().unwrap();
        conn.command("NOOP").unwrap();
        let recovered = conn.into_inner().unwrap();
        assert!(written_str(&recovered).contains("a1 NOOP\r\n"));
    }

    #[test]
    fn command_allowlist_refuses_before_write() {
        let denied = [
            "STORE 1 +FLAGS (\\Seen)",
            "UID STORE 1 +FLAGS (\\Seen)",
            "UID STORE 1 +FLAGS.SILENT (\\Seen)",
            "UID COPY 1 INBOX",
            "UID MOVE 1 INBOX",
            "COPY 1 INBOX",
            "MOVE 1 INBOX",
            "APPEND INBOX (\\Seen) {1}",
            "APPEND \"Drafts\" {1+}",
            "APPEND \"drafts\" {1}",
            "APPEND \"Drafts\" {1}",
            "EXPUNGE",
            "expunge",
            "UID EXPUNGE 1",
            "DELETE INBOX",
            "CREATE INBOX",
            "CREATE \"Folders/\"",
            "CREATE \"Folders//X\"",
            "CREATE \"Labels/a*b\"",
            "RENAME A B",
            "SUBSCRIBE INBOX",
            "UNSUBSCRIBE INBOX",
            "CLOSE",
            "close",
            "CHECK",
            "SEARCH ALL",
            "FETCH 1 (UID)",
            "UID",
            "UIDSTORE 1 +FLAGS.SILENT (\\Seen)",
            "SELECTX INBOX",
            "SELECT INBOX EXPUNGE",
            "",
            "NOOP\r\nSELECT INBOX",
            "LOGIN \"a\nb\" \"c\"",
        ];
        for cmd in denied {
            let script = Script::new(Vec::<u8>::new());
            let mut conn = Conn::new(script.clone());
            let err = conn.command(cmd).unwrap_err();
            assert!(
                matches!(err, Error::InvalidArgument(_)),
                "expected refusal for {cmd:?}, got {err}"
            );
            assert!(
                script.written().is_empty(),
                "refused command was written: {cmd:?}"
            );
        }
    }

    #[test]
    fn rejected_command_does_not_consume_a_tag() {
        let script = Script::new(b"a1 OK\r\n".to_vec());
        let mut conn = Conn::new(script.clone());
        assert!(conn.command("EXPUNGE").is_err());
        conn.command("NOOP").unwrap();
        assert_eq!(written_str(&script), "a1 NOOP\r\n");
    }

    #[test]
    fn allowed_commands_are_written() {
        let allowed = ["CAPABILITY", "STARTTLS", "NOOP", "LOGOUT", "uid search ALL"];
        for cmd in allowed {
            let script = Script::new(b"a1 OK\r\n".to_vec());
            let mut conn = Conn::new(script.clone());
            conn.command(cmd).unwrap();
            let wire = written_str(&script);
            assert!(wire.starts_with("a1 "), "{wire}");
            assert!(wire.contains(cmd), "{wire}");
        }
    }

    #[test]
    fn login_quotes_and_hides_secrets_from_errors() {
        let script = Script::new(b"a1 OK logged in\r\n".to_vec());
        let conn = Conn::new(script.clone());
        Session::login(conn, "a\"b", "c\\d").unwrap();
        assert!(written_str(&script).contains("LOGIN \"a\\\"b\" \"c\\\\d\""));

        let script = Script::new(b"a1 NO denied\r\n".to_vec());
        let err = force_err(Session::login(Conn::new(script), "user", "super-secret"));
        let msg = err.to_string();
        assert!(msg.contains("denied"));
        assert!(!msg.contains("super-secret"));
        assert!(!msg.contains("user"));

        let err = force_err(Session::login(
            Conn::new(Script::new(Vec::<u8>::new())),
            "bad\nname",
            "super-secret",
        ));
        let msg = err.to_string();
        assert!(matches!(err, Error::InvalidArgument(_)));
        assert!(!msg.contains("super-secret"));
        assert!(!msg.contains("bad"));
        assert!(!msg.contains('\n'));
    }

    #[test]
    fn argument_injection_never_reaches_the_wire() {
        let script = Script::new(b"a1 OK\r\n".to_vec());
        let mut session = Session::login(Conn::new(script.clone()), "u", "p").unwrap();
        let len = script.written().len();
        for bad in ["box\rname", "box\nname", "box\0name", "böx", "box\u{7f}"] {
            let err = session.examine(bad).unwrap_err();
            assert!(matches!(err, Error::InvalidArgument(_)), "{bad:?} -> {err}");
            assert_eq!(script.written().len(), len);
        }
        let query = Search {
            text: Some("hello\r\nUID SEARCH".to_string()),
            ..Search::default()
        };
        assert!(matches!(
            session.uid_search(&query),
            Err(Error::InvalidArgument(_))
        ));
        assert_eq!(script.written().len(), len);
    }

    #[test]
    fn quotes_and_dates_and_uid_limits() {
        assert_eq!(quote_arg("a\"b\\c").unwrap(), "\"a\\\"b\\\\c\"");
        assert_eq!(format_imap_date("2024-02-29").unwrap(), "29-Feb-2024");
        assert_eq!(format_imap_date("2026-01-05").unwrap(), "5-Jan-2026");
        assert_eq!(format_imap_date("1900-02-28").unwrap(), "28-Feb-1900");
        assert_eq!(format_imap_date("2000-02-29").unwrap(), "29-Feb-2000");
        assert!(format_imap_date("2023-02-29").is_err());
        assert!(format_imap_date("2026-02-31").is_err());
        assert!(format_imap_date("2026-13-01").is_err());
        assert!(format_imap_date("2026-00-01").is_err());
        assert!(format_imap_date("2026-1-01").is_err());
        assert!(format_imap_date("26-01-01").is_err());
        assert!(format_imap_date("2026-01-00").is_err());

        let mut session =
            Session::login(Conn::new(Script::new(b"a1 OK\r\n".to_vec())), "u", "p").unwrap();
        assert!(session.fetch_headers(&[]).unwrap().is_empty());
        let too_many = vec![1u32; 201];
        assert!(matches!(
            session.fetch_headers(&too_many),
            Err(Error::InvalidArgument(_))
        ));
        assert!(matches!(
            session.fetch_headers(&[0]),
            Err(Error::InvalidArgument(_))
        ));
        assert!(matches!(
            session.fetch_message(0, 10),
            Err(Error::InvalidArgument(_))
        ));
    }

    #[test]
    fn list_examine_search_and_fetch_round_trip() {
        let header = b"Subject: Hi\r\n";
        let mut raw = Vec::new();
        raw.extend_from_slice(b"a1 OK login\r\n");
        raw.extend_from_slice(b"* LIST (\\Noselect) \"/\" {4}\r\nJunk\r\n");
        raw.extend_from_slice(b"* LIST () NIL \"INBOX\"\r\n");
        raw.extend_from_slice(b"* LIST (\\HasNoChildren \\NonExistent) \"/\" Archive\r\n");
        raw.extend_from_slice(b"* 1 EXISTS\r\n");
        raw.extend_from_slice(b"a2 OK list\r\n");
        raw.extend_from_slice(b"* 5 EXISTS\r\n");
        raw.extend_from_slice(b"* 0 RECENT\r\n");
        raw.extend_from_slice(b"* FLAGS (\\Seen \\Answered)\r\n");
        raw.extend_from_slice(b"* OK [UIDVALIDITY 9] UIDs valid\r\n");
        raw.extend_from_slice(b"a3 OK [READ-ONLY] examine\r\n");
        raw.extend_from_slice(b"* SEARCH 9 3 3 1\r\n");
        raw.extend_from_slice(b"a4 OK search\r\n");
        raw.extend_from_slice(
            b"*  2   FETCH  ( UID  3  FLAGS ( \\Seen ) RFC822.SIZE 13 BODY[HEADER.FIELDS (DATE FROM TO CC SUBJECT MESSAGE-ID)]<0> {",
        );
        raw.extend_from_slice(header.len().to_string().as_bytes());
        raw.extend_from_slice(b"}\r\n");
        raw.extend_from_slice(header);
        raw.extend_from_slice(b")\r\n");
        raw.extend_from_slice(b"a5 OK fetch\r\n");
        let payload = b"* a1 OK\r\n";
        raw.extend_from_slice(b"* 4 FETCH (UID 9 FLAGS (\\Flagged) RFC822.SIZE 9 BODY[] {");
        raw.extend_from_slice(payload.len().to_string().as_bytes());
        raw.extend_from_slice(b"+}\r\n");
        raw.extend_from_slice(payload);
        raw.extend_from_slice(b")\r\n");
        raw.extend_from_slice(b"a6 OK fetch\r\n");
        raw.extend_from_slice(b"* BYE\r\na7 OK logout\r\n");

        let script = Script::new(raw);
        let mut session = Session::login(Conn::new(script.clone()), "me", "pw").unwrap();
        let boxes = session.list_mailboxes().unwrap();
        assert_eq!(
            boxes,
            vec![
                Mailbox {
                    name: "Junk".to_string(),
                    noselect: true,
                },
                Mailbox {
                    name: "INBOX".to_string(),
                    noselect: false,
                },
                Mailbox {
                    name: "Archive".to_string(),
                    noselect: true,
                },
            ]
        );
        session.examine("INBOX").unwrap();
        let uids = session
            .uid_search(&Search {
                from: Some("a@b.c".to_string()),
                subject: Some("hi \"x\"".to_string()),
                since: Some("2024-02-29".to_string()),
                before: Some("2026-01-05".to_string()),
                unseen: true,
                max_uid: Some(40),
                ..Search::default()
            })
            .unwrap();
        assert_eq!(uids, vec![1, 3, 3, 9]);
        let headers = session.fetch_headers(&[3, 9]).unwrap();
        assert_eq!(headers.len(), 1);
        assert_eq!(headers[0].uid, 3);
        assert_eq!(headers[0].flags, vec!["\\Seen".to_string()]);
        assert_eq!(headers[0].size, Some(13));
        assert_eq!(headers[0].data.as_deref(), Some(header.as_slice()));
        let message = session.fetch_message(9, 100).unwrap().unwrap();
        assert_eq!(message.uid, 9);
        assert_eq!(message.data.as_deref(), Some(payload.as_slice()));
        assert_eq!(message.flags, vec!["\\Flagged".to_string()]);
        session.logout();

        let wire = written_str(&script);
        assert!(wire.contains("a1 LOGIN \"me\" \"pw\"\r\n"));
        assert!(wire.contains("a2 LIST \"\" \"*\"\r\n"));
        assert!(wire.contains("a3 EXAMINE \"INBOX\"\r\n"));
        assert!(wire.contains(
            "a4 UID SEARCH UID 1:40 FROM \"a@b.c\" SUBJECT \"hi \\\"x\\\"\" SINCE 29-Feb-2024 BEFORE 5-Jan-2026 UNSEEN\r\n"
        ));
        assert!(wire.contains(
            "a5 UID FETCH 3,9 (UID FLAGS RFC822.SIZE BODY.PEEK[HEADER.FIELDS (DATE FROM TO CC SUBJECT MESSAGE-ID REPLY-TO AUTHENTICATION-RESULTS RECEIVED X-PM-SPAM-ACTION X-PM-SPAMSCORE X-PM-ORIGIN)]<0.65536>)\r\n"
        ));
        assert!(wire.contains("a6 UID FETCH 9 (UID FLAGS RFC822.SIZE BODY.PEEK[]<0.100>)\r\n"));
        assert!(wire.contains("a7 LOGOUT\r\n"));
        assert!(!wire.contains("SELECT"));
        assert!(!wire.contains("STORE"));
        assert!(!wire.contains("EXPUNGE"));
        assert!(!wire.contains("BODY["));
    }

    #[test]
    fn fetch_nil_odd_spacing_and_ignored_untagged() {
        let mut raw = b"*  4   FETCH   (  UID   15   FLAGS   (   \\Seen    )   RFC822.SIZE    3   BODY[]<0>   {3}\r\nabc)\r\n".to_vec();
        raw.extend_from_slice(b"* 1 FETCH (UID 8 FLAGS () RFC822.SIZE NIL BODY[] NIL)\r\n");
        raw.extend_from_slice(b"* 2 EXISTS\r\n* OK [UIDNEXT 3] next\r\n");
        raw.extend_from_slice(b"a1 OK\r\n");
        let script = Script::new(raw);
        let mut conn = Conn::new(script.clone());
        let responses = conn
            .command("UID FETCH 15,8 (UID FLAGS RFC822.SIZE BODY.PEEK[]<0.3>)")
            .unwrap();
        assert_eq!(responses.len(), 4);
        let first = parse_fetch(&responses[0]).unwrap().expect("fetch");
        assert_eq!(
            first,
            Fetched {
                uid: 15,
                flags: vec!["\\Seen".to_string()],
                size: Some(3),
                data: Some(b"abc".to_vec()),
            }
        );
        let second = parse_fetch(&responses[1]).unwrap().expect("fetch");
        assert_eq!(second.uid, 8);
        assert!(second.flags.is_empty());
        assert_eq!(second.size, None);
        assert_eq!(second.data, None);
        assert!(kind_of(&responses[2]) == Kind::Other);
    }

    #[test]
    fn tagged_no_is_truncated_and_continuation_is_an_error() {
        let mut text = String::new();
        for _ in 0..250 {
            text.push('x');
        }
        let raw = format!("a1 NO {text}\r\n").into_bytes();
        let err = Conn::new(Script::new(raw)).command("NOOP").unwrap_err();
        match err {
            Error::Server(body) => {
                assert_eq!(body.chars().count(), 200);
                assert!(body.chars().all(|c| c == 'x'));
            }
            other => panic!("unexpected {other:?}"),
        }
        let err = Conn::new(Script::new(b"+ ready\r\n".to_vec()))
            .command("NOOP")
            .unwrap_err();
        assert!(err.to_string().contains("continuation"));
        let err = Conn::new(Script::new(b"a9 OK\r\n".to_vec()))
            .command("NOOP")
            .unwrap_err();
        assert!(matches!(err, Error::Protocol(_)));
    }

    #[test]
    fn overlong_line_and_literal_are_refused() {
        let mut line = vec![b'A'; MAX_LINE - 1];
        line.extend_from_slice(b"\r\n");
        let err = Conn::new(Script::new(line)).read_greeting().unwrap_err();
        assert!(err.to_string().contains("64KiB"));

        let mut ok = vec![b' '; MAX_LINE - 2];
        ok[0] = b'*';
        ok[1] = b' ';
        ok[2] = b'O';
        ok[3] = b'K';
        ok.extend_from_slice(b"\r\n");
        assert_eq!(ok.len(), MAX_LINE);
        Conn::new(Script::new(ok)).read_greeting().unwrap();

        let huge = format!("* OK {{{}}}\r\n", MAX_LITERAL + 1);
        let err = Conn::new(Script::new(huge.into_bytes()))
            .read_greeting()
            .unwrap_err();
        assert!(err.to_string().contains("8MiB"), "{err}");

        let exact = format!("* OK {{{MAX_LITERAL}}}\r\n");
        let err = Conn::new(Script::new(exact.into_bytes()))
            .read_greeting()
            .unwrap_err();
        assert!(
            !err.to_string().contains("8MiB"),
            "exact 8MiB must be accepted and then hit EOF, got {err}"
        );
        assert!(err.to_string().contains("end of literal"));
    }

    #[test]
    fn response_over_16mib_is_refused() {
        let mut raw = Vec::new();
        raw.extend_from_slice(format!("* OK {{{MAX_LITERAL}}}\r\n").as_bytes());
        raw.extend(std::iter::repeat_n(b'x', MAX_LITERAL));
        raw.extend_from_slice(format!("{{{MAX_LITERAL}}}\r\n").as_bytes());
        let err = Conn::new(Script::new(raw)).read_greeting().unwrap_err();
        assert!(err.to_string().contains("16MiB"), "{err}");
    }

    #[test]
    fn too_many_untagged_responses() {
        let mut raw = Vec::new();
        for _ in 0..=MAX_UNTAGGED {
            raw.extend_from_slice(b"* 1 EXISTS\r\n");
        }
        raw.extend_from_slice(b"a1 OK\r\n");
        let err = Conn::new(Script::new(raw)).command("NOOP").unwrap_err();
        assert!(err.to_string().contains("too many"), "{err}");
    }

    #[test]
    fn literal_bytes_that_look_like_responses_stay_inside_the_literal() {
        let payload = b"* a1 OK\r\n";
        let mut raw = Vec::new();
        raw.extend_from_slice(b"* 1 FETCH (UID 1 FLAGS () RFC822.SIZE 9 BODY[] {9}\r\n");
        raw.extend_from_slice(payload);
        raw.extend_from_slice(b")\r\na1 OK done\r\n");
        let mut session_conn = Conn::new(Script::new(raw));
        let responses = session_conn
            .command("UID FETCH 1 (UID FLAGS RFC822.SIZE BODY.PEEK[]<0.9>)")
            .unwrap();
        assert_eq!(responses.len(), 1);
        let fetched = parse_fetch(&responses[0]).unwrap().expect("fetch");
        assert_eq!(fetched.data.as_deref(), Some(payload.as_slice()));
    }

    #[test]
    fn deep_and_truncated_fetch_does_not_panic() {
        let mut raw = b"* 1 FETCH ".to_vec();
        raw.extend(std::iter::repeat_n(b'(', 20));
        raw.extend_from_slice(b"UID 1");
        raw.extend(std::iter::repeat_n(b')', 20));
        raw.extend_from_slice(b"\r\na1 OK\r\n");
        let responses = Conn::new(Script::new(raw))
            .command("UID FETCH 1 (UID)")
            .unwrap();
        assert_eq!(responses.len(), 1);
        assert!(parse_fetch(&responses[0]).is_err());

        let framed = b"* 1 FETCH ((((((((((((((((((((UID 1))))))))))))))))))))\r\n";
        assert!(parse_fetch(framed).is_err());
        assert!(parse_fetch(b"* 1 FETCH (UID 1\r\n").is_err());
        assert!(parse_fetch(b"").is_err());
    }

    #[test]
    fn empty_search_and_logout_on_eof() {
        let script = Script::new(b"a1 OK\r\n* SEARCH\r\na2 OK\r\n".to_vec());
        let mut session = Session::login(Conn::new(script.clone()), "u", "p").unwrap();
        let uids = session.uid_search(&Search::default()).unwrap();
        assert!(uids.is_empty());
        assert!(written_str(&script).contains("UID SEARCH ALL\r\n"));
        session.logout();

        let script = Script::new(b"a1 OK\r\n".to_vec());
        let session = Session::login(Conn::new(script.clone()), "u", "p").unwrap();
        session.logout();
        assert!(written_str(&script).contains("LOGOUT"));
    }

    struct XorShift {
        state: u32,
    }

    impl XorShift {
        fn new(seed: u32) -> Self {
            Self {
                state: if seed == 0 { 1 } else { seed },
            }
        }

        fn next(&mut self) -> u32 {
            let mut x = self.state;
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            self.state = x;
            x
        }
    }

    #[test]
    fn parser_and_reader_do_not_panic_on_random_or_truncated_input() {
        let sample = b"* 1 FETCH (UID 1 FLAGS (\\Seen) RFC822.SIZE 3 BODY[HEADER.FIELDS (DATE FROM)] {3}\r\nabc)\r\n";
        for i in 0..=sample.len() {
            let _ = parse_fuzz(&sample[..i]);
            let _ = Conn::new(Script::new(sample[..i].to_vec())).read_greeting();
            let _ = Conn::new(Script::new(sample[..i].to_vec())).command("NOOP");
        }

        let mut rng = XorShift::new(0xA5C3_19E7);
        for n in 0..2500 {
            let len = (rng.next() as usize) % 400;
            let mut buf = vec![0u8; len];
            for byte in &mut buf {
                *byte = rng.next() as u8;
            }
            if n % 7 == 0 {
                let mut prefixed = b"* 1 FETCH (".to_vec();
                prefixed.extend_from_slice(&buf);
                buf = prefixed;
            }
            let cut = (rng.next() as usize) % buf.len().saturating_add(1);
            let truncated = buf.get(..cut).unwrap_or(&buf);
            let _ = parse_fuzz(&buf);
            let _ = parse_fuzz(truncated);
            let _ = Conn::new(Script::new(buf.clone())).read_greeting();
            let _ = Conn::new(Script::new(truncated.to_vec())).command("NOOP");
        }
    }

    #[test]
    fn unsolicited_fetch_without_uid_is_skipped() {
        let mut raw = b"a1 OK LOGIN\r\n".to_vec();
        raw.extend_from_slice(b"* 3 FETCH (FLAGS (\\Seen))\r\n");
        raw.extend_from_slice(
            b"* 5 FETCH (UID 9 FLAGS () RFC822.SIZE 10 BODY[HEADER.FIELDS (SUBJECT)] {4}\r\n",
        );
        raw.extend_from_slice(b"S: x)\r\n");
        raw.extend_from_slice(b"a2 OK done\r\n");
        let mut session = Session::login(Conn::new(Script::new(raw)), "u", "p").unwrap();
        let got = session.fetch_headers(&[9]).unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].uid, 9);
        assert_eq!(got[0].data.as_deref(), Some(b"S: x".as_slice()));
    }

    #[test]
    fn fetch_header_section_with_origin_is_one_atom() {
        let mut raw = b"* 1 FETCH (UID 4 FLAGS () BODY[HEADER.FIELDS (DATE FROM TO CC SUBJECT MESSAGE-ID)]<0> {9}\r\n".to_vec();
        raw.extend_from_slice(b"Subject\r\n)\r\na1 OK\r\n");
        let responses = Conn::new(Script::new(raw))
            .command("UID FETCH 4 (UID FLAGS RFC822.SIZE BODY.PEEK[HEADER.FIELDS (DATE FROM TO CC SUBJECT MESSAGE-ID REPLY-TO AUTHENTICATION-RESULTS RECEIVED X-PM-SPAM-ACTION X-PM-SPAMSCORE X-PM-ORIGIN)]<0.65536>)")
            .unwrap();
        let fetched = parse_fetch(&responses[0]).unwrap().expect("fetch");
        assert_eq!(fetched.uid, 4);
        assert_eq!(fetched.data.as_deref(), Some(b"Subject\r\n".as_slice()));
    }

    fn push_u32(out: &mut Vec<u8>, mut n: u32) {
        let mut tmp = [0u8; 10];
        let mut i = tmp.len();
        if n == 0 {
            out.push(b'0');
            return;
        }
        while n > 0 {
            i -= 1;
            tmp[i] = b'0' + u8::try_from(n % 10).unwrap_or(0);
            n /= 10;
        }
        if let Some(digits) = tmp.get(i..) {
            out.extend_from_slice(digits);
        }
    }

    #[test]
    fn search_on_14k_message_mailbox() {
        let mut script = b"a1 OK LOGIN\r\n* SEARCH".to_vec();
        for uid in 1..=14_000u32 {
            script.push(b' ');
            push_u32(&mut script, uid);
        }
        assert!(
            script.len() > MAX_LINE,
            "fixture must exceed the ordinary line cap, was {}",
            script.len()
        );
        script.extend_from_slice(b"\r\na2 OK done\r\n");
        let mut session = Session::login(Conn::new(Script::new(script)), "u", "p").unwrap();
        let uids = session.uid_search(&Search::default()).unwrap();
        assert_eq!(uids.len(), 14_000);
        assert_eq!(uids.first().copied(), Some(1));
        assert_eq!(uids.last().copied(), Some(14_000));
    }

    #[test]
    fn million_uid_search_parses_quickly() {
        let mut line = Vec::with_capacity(8_000_000);
        line.extend_from_slice(b"* SEARCH");
        for uid in 1..=1_000_000u32 {
            line.push(b' ');
            push_u32(&mut line, uid);
        }
        line.extend_from_slice(b"\r\n");
        let started = std::time::Instant::now();
        let uids = parse_search(&line).unwrap();
        let elapsed = started.elapsed();
        assert_eq!(uids.len(), 1_000_000);
        assert_eq!(uids.first().copied(), Some(1));
        assert_eq!(uids.get(123_456).copied(), Some(123_457));
        assert_eq!(uids.last().copied(), Some(1_000_000));
        assert!(
            elapsed.as_secs() < 2,
            "parsing 1_000_000 UIDs took {elapsed:?}"
        );
    }

    #[test]
    fn search_line_over_16mib_is_refused() {
        let mut line = b"* SEARCH ".to_vec();
        line.resize(MAX_RESPONSE + 1, b'1');
        line.extend_from_slice(b"\r\na1 OK\r\n");
        let err = Conn::new(Script::new(line))
            .command("UID SEARCH ALL")
            .unwrap_err();
        assert!(err.to_string().contains("16MiB"), "{err}");
    }

    #[test]
    fn crlf_split_across_reads_still_completes() {
        let mut raw = vec![b' '; 1024];
        raw[0] = b'*';
        raw[1] = b' ';
        raw[2] = b'O';
        raw[3] = b'K';
        raw[1023] = b'\r';
        raw.push(b'\n');
        Conn::new(Script::new(raw)).read_greeting().unwrap();
    }

    fn fetch_bodies(count: u32, literal_len: usize) -> Vec<u8> {
        let mut script = b"a1 OK LOGIN\r\n".to_vec();
        let lit = vec![b'a'; literal_len];
        for uid in 1..=count {
            let head = format!(
                "* {uid} FETCH (UID {uid} BODY[HEADER.FIELDS (SUBJECT)] {{{literal_len}}}\r\n"
            );
            script.extend_from_slice(head.as_bytes());
            script.extend_from_slice(&lit);
            script.extend_from_slice(b")\r\n");
        }
        script.extend_from_slice(b"a2 OK done\r\n");
        script
    }

    #[test]
    fn three_large_literals_under_command_cap_are_kept() {
        let literal_len = 7 << 20;
        let script = fetch_bodies(3, literal_len);
        let mut session = Session::login(Conn::new(Script::new(script)), "u", "p").unwrap();
        let fetched = session.fetch_headers(&[1, 2, 3]).unwrap();
        let total: usize = fetched
            .iter()
            .map(|item| item.data.as_ref().map_or(0, Vec::len))
            .sum();
        assert_eq!(fetched.len(), 3);
        assert!(total > 16 << 20, "total {total}");
        assert!(total < MAX_COMMAND_BYTES, "total {total}");
    }

    #[test]
    fn command_responses_over_48mib_are_refused() {
        let literal_len = 7 << 20;
        let script = fetch_bodies(7, literal_len);
        let mut session = Session::login(Conn::new(Script::new(script)), "u", "p").unwrap();
        let uids: Vec<u32> = (1..=7).collect();
        let err = session.fetch_headers(&uids).unwrap_err();
        assert!(err.to_string().contains("48MiB"), "{err}");
    }

    fn script_ok(lines: &[&str]) -> Script {
        let mut raw = Vec::new();
        for line in lines {
            raw.extend_from_slice(line.as_bytes());
            if !line.ends_with("\r\n") {
                raw.extend_from_slice(b"\r\n");
            }
        }
        Script::new(raw)
    }

    fn logged_in(lines: &[&str]) -> (Session<Script>, Script) {
        let mut all = vec!["a1 OK login"];
        all.extend_from_slice(lines);
        let script = script_ok(&all);
        let session = Session::login(Conn::new(script.clone()), "u", "p").unwrap();
        (session, script)
    }

    #[test]
    fn select_tracks_mailbox_and_examine_is_read_only() {
        let script = script_ok(&[
            "a1 OK [READ-WRITE] selected",
            "a2 OK [READ-ONLY] examined",
            "a3 NO missing",
            "a4 OK [READ-WRITE] selected",
            "a5 OK unselected",
        ]);
        let mut conn = Conn::new(script.clone());
        conn.command("SELECT \"INBOX\"").unwrap();
        assert_eq!(conn.mailbox, MailboxState::Selected("INBOX".into()));
        conn.command("EXAMINE \"Trash\"").unwrap();
        assert_eq!(conn.mailbox, MailboxState::Examined("Trash".into()));
        let len = script.written().len();
        let err = conn
            .command("UID STORE 1 +FLAGS.SILENT (\\Seen)")
            .unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)), "{err}");
        assert_eq!(script.written().len(), len);
        assert!(conn.command("SELECT \"Missing\"").is_err());
        assert_eq!(conn.mailbox, MailboxState::None);
        conn.command("SeLeCt \"Folders/My Stuff\"").unwrap();
        assert_eq!(
            conn.mailbox,
            MailboxState::Selected("Folders/My Stuff".into())
        );
        conn.command("UNSELECT").unwrap();
        assert_eq!(conn.mailbox, MailboxState::None);
        let wire = written_str(&script);
        assert!(wire.contains("a1 SELECT \"INBOX\"\r\n"));
        assert!(wire.contains("a2 EXAMINE \"Trash\"\r\n"));
        assert!(wire.contains("a4 SeLeCt \"Folders/My Stuff\"\r\n"));
        assert!(wire.contains("a5 UNSELECT\r\n"));
        assert!(!wire.contains("STORE"));
    }

    #[test]
    fn failed_select_clears_a_previous_mailbox() {
        let script = script_ok(&["a1 OK selected", "a2 NO no such mailbox"]);
        let mut conn = Conn::new(script.clone());
        conn.command("SELECT INBOX").unwrap();
        assert!(conn.command("SELECT \"Gone\"").is_err());
        assert_eq!(conn.mailbox, MailboxState::None);
        let len = script.written().len();
        assert!(conn.command("UID MOVE 1 Archive").is_err());
        assert_eq!(script.written().len(), len);
    }

    #[test]
    fn dangerous_commands_stay_refused_after_select() {
        let script = script_ok(&["a1 OK [READ-WRITE] selected"]);
        let mut conn = Conn::new(script.clone());
        conn.command("SELECT INBOX").unwrap();
        let len = script.written().len();
        let denied = [
            "EXPUNGE",
            "CLOSE",
            "DELETE INBOX",
            "RENAME A B",
            "SUBSCRIBE INBOX",
            "STORE 1 +FLAGS.SILENT (\\Seen)",
            "UID STORE 1 FLAGS (\\Seen)",
            "UID STORE 1 +FLAGS (\\Seen)",
            "UID STORE 1 FLAGS.SILENT (\\Seen)",
            "UID STORE 1 +FLAGS.SILENT (\\Answered)",
            "UID STORE 1 +FLAGS.SILENT (\\Draft)",
            "UID STORE 1 +FLAGS.SILENT (\\Deleted)",
            "UID STORE 1 -FLAGS.SILENT (\\Deleted)",
            "UID EXPUNGE 1",
            "UID EXPUNGE 1:*",
            "APPEND \"INBOX\" {1}",
            "APPEND \"Trash\" (\\Seen) {1}",
            "APPEND \"Sent\" {1}",
            "COPY 1 Archive",
            "MOVE 1 Archive",
        ];
        for cmd in denied {
            let err = conn.command(cmd).unwrap_err();
            assert!(
                matches!(err, Error::InvalidArgument(_)),
                "expected refusal for {cmd:?}, got {err}"
            );
            assert_eq!(script.written().len(), len, "wrote {cmd:?}");
        }
        assert_eq!(conn.mailbox, MailboxState::Selected("INBOX".into()));
    }

    #[test]
    fn label_mailbox_allows_deleted_and_uid_expunge_only() {
        let script = script_ok(&[
            "a1 OK [READ-WRITE] selected",
            "a2 OK stored",
            "a3 OK expunged",
        ]);
        let mut conn = Conn::new(script.clone());
        conn.command("SELECT \"Labels/Work\"").unwrap();
        let len = script.written().len();
        assert!(
            conn.command("UID STORE 1 -FLAGS.SILENT (\\Deleted)")
                .is_err()
        );
        assert!(conn.command("UID STORE 1 FLAGS (\\Deleted)").is_err());
        assert_eq!(script.written().len(), len);
        conn.command("UID STORE 1,2 +FLAGS.SILENT (\\Deleted)")
            .unwrap();
        conn.command("uid expunge 1,2").unwrap();
        let wire = written_str(&script);
        assert!(wire.contains("UID STORE 1,2 +FLAGS.SILENT (\\Deleted)\r\n"));
        assert!(wire.contains("uid expunge 1,2\r\n"));
        assert!(!wire.contains("\r\nEXPUNGE"));
    }

    #[test]
    fn list_argument_containing_expunge_is_not_a_verb() {
        let script = script_ok(&["a1 OK listed"]);
        let mut conn = Conn::new(script.clone());
        conn.command("LIST \"\" \"UID STORE 1 +FLAGS.SILENT (\\Seen)\"")
            .unwrap();
        let wire = written_str(&script);
        assert!(wire.contains("LIST \"\" \"UID STORE 1 +FLAGS.SILENT (\\Seen)\"\r\n"));
        assert!(!wire.contains("\r\nUID STORE"));
    }

    #[test]
    fn uid_move_and_copy_return_copyuid_pairs() {
        let (mut session, script) = logged_in(&[
            "a2 OK [READ-WRITE] selected",
            "* OK [COPYUID 38505 304,319:320 3956:3958] Moved",
            "a3 OK done",
            "a4 OK [COPYUID 9 320:319 10:11] copied",
        ]);
        session.select("INBOX").unwrap();
        let moved = session.uid_move(&[304, 319, 320], "Trash").unwrap();
        assert_eq!(moved, vec![(304, 3956), (319, 3957), (320, 3958)]);
        let copied = session.uid_copy(&[7], "Labels/My Work").unwrap();
        assert_eq!(copied, vec![(319, 10), (320, 11)]);
        let wire = written_str(&script);
        assert!(wire.contains("a3 UID MOVE 304,319,320 \"Trash\"\r\n"));
        assert!(wire.contains("a4 UID COPY 7 \"Labels/My Work\"\r\n"));
    }

    #[test]
    fn copyuid_absent_tagged_wins_and_mismatch_errors() {
        assert_eq!(
            copyuid_pairs(&[], b"a1 OK done\r\n").unwrap(),
            Vec::<(u32, u32)>::new()
        );
        let untagged = vec![b"* OK [COPYUID 1 4 8] moved\r\n".to_vec()];
        assert_eq!(
            copyuid_pairs(&untagged, b"a1 OK done\r\n").unwrap(),
            vec![(4, 8)]
        );
        assert_eq!(
            copyuid_pairs(&untagged, b"a1 OK [COPYUID 2 1 9] done\r\n").unwrap(),
            vec![(1, 9)]
        );
        assert!(copyuid_pairs(&[], b"a1 OK [COPYUID 1 1,2 3] x\r\n").is_err());
        assert!(copyuid_pairs(&[], b"a1 OK [COPYUID 1 1:100000000 1] x\r\n").is_err());
        assert!(append_uid(&[], b"a1 OK [APPENDUID 5 42] saved\r\n").unwrap() == Some(42));
        assert!(append_uid(&[], b"a1 OK done\r\n").unwrap().is_none());
        let untagged = vec![b"* OK [APPENDUID 1 7] x\r\n".to_vec()];
        assert_eq!(append_uid(&untagged, b"a1 OK done\r\n").unwrap(), Some(7));
    }

    #[test]
    fn uid_store_flags_and_write_cap() {
        let (mut session, script) = logged_in(&[
            "a2 OK [READ-WRITE] selected",
            "a3 OK stored",
            "a4 OK stored",
        ]);
        session.select("INBOX").unwrap();
        session
            .uid_store_flags(&[4, 9], true, &[Flag::Seen, Flag::Flagged, Flag::Seen])
            .unwrap();
        session.uid_store_flags(&[4], false, &[Flag::Seen]).unwrap();
        let wire = written_str(&script);
        assert!(wire.contains("a3 UID STORE 4,9 +FLAGS.SILENT (\\Seen \\Flagged)\r\n"));
        assert!(wire.contains("a4 UID STORE 4 -FLAGS.SILENT (\\Seen)\r\n"));
        let len = script.written().len();
        assert!(session.uid_store_flags(&[], true, &[Flag::Seen]).is_err());
        assert!(session.uid_store_flags(&[0], true, &[Flag::Seen]).is_err());
        assert!(session.uid_store_flags(&[1], true, &[]).is_err());
        let too_many: Vec<u32> = (1..=51).collect();
        assert!(matches!(
            session.uid_move(&too_many, "Archive"),
            Err(Error::InvalidArgument(_))
        ));
        assert_eq!(script.written().len(), len);
        assert!(session.uid_copy(&too_many, "Archive").is_err());
        assert!(session.uid_move(&[1], "").is_err());
        assert_eq!(script.written().len(), len);
    }

    #[test]
    fn remove_label_selects_stores_expunges_and_unselects() {
        let (mut session, script) = logged_in(&[
            "a2 OK [READ-WRITE] selected",
            "a3 OK stored",
            "a4 OK expunged",
            "a5 OK unselected",
        ]);
        session.remove_label("Labels/My Work", &[8, 9]).unwrap();
        assert_eq!(session.conn.mailbox, MailboxState::None);
        let wire = written_str(&script);
        assert!(wire.contains("a2 SELECT \"Labels/My Work\"\r\n"));
        assert!(wire.contains("a3 UID STORE 8,9 +FLAGS.SILENT (\\Deleted)\r\n"));
        assert!(wire.contains("a4 UID EXPUNGE 8,9\r\n"));
        assert!(wire.contains("a5 UNSELECT\r\n"));
        assert!(!wire.contains("\r\nEXPUNGE"));
        assert!(!wire.contains("\r\nCLOSE"));

        let (mut session, script) = logged_in(&[]);
        let len = script.written().len();
        for bad in [
            "INBOX",
            "Trash",
            "Labels",
            "Labels/",
            "Folders/X",
            "labels/X",
            "",
        ] {
            let err = session.remove_label(bad, &[1]).unwrap_err();
            assert!(matches!(err, Error::InvalidArgument(_)), "{bad} -> {err}");
            assert_eq!(script.written().len(), len, "{bad}");
        }
    }

    #[test]
    fn remove_label_unselects_when_store_fails() {
        let (mut session, script) = logged_in(&[
            "a2 OK [READ-WRITE] selected",
            "a3 NO cannot store",
            "a4 OK unselected",
        ]);
        let err = session.remove_label("Labels/Work", &[1]).unwrap_err();
        assert!(matches!(err, Error::Server(_)), "{err}");
        assert!(written_str(&script).contains("a4 UNSELECT\r\n"));
        assert_eq!(session.conn.mailbox, MailboxState::None);
        assert!(!written_str(&script).contains("EXPUNGE"));
    }

    #[test]
    fn create_restricts_prefixes_and_wildcards() {
        let (mut session, script) = logged_in(&["a2 OK created", "a3 OK created"]);
        session.create("Folders/My Stuff").unwrap();
        session.create("Labels/Work/2026").unwrap();
        let wire = written_str(&script);
        assert!(wire.contains("a2 CREATE \"Folders/My Stuff\"\r\n"));
        assert!(wire.contains("a3 CREATE \"Labels/Work/2026\"\r\n"));
        let len = script.written().len();
        for bad in [
            "INBOX",
            "Trash",
            "Folders",
            "Labels",
            "Folders/",
            "Labels/",
            "Folders//X",
            "Labels/a*b",
            "Folders/a%b",
            "Folders/a/b/",
            "böx",
            "Folders/böx",
        ] {
            let err = session.create(bad).unwrap_err();
            assert!(matches!(err, Error::InvalidArgument(_)), "{bad} -> {err}");
            assert_eq!(script.written().len(), len, "{bad}");
        }
    }

    #[test]
    fn append_draft_waits_for_continuation() {
        let (mut session, script) = logged_in(&[
            "+ Ready for literal data",
            "* 1 EXISTS",
            "a2 OK [APPENDUID 38505 3955] Append completed",
        ]);
        let uid = session.append_draft(b"hello").unwrap();
        assert_eq!(uid, Some(3955));
        let wire = written_str(&script);
        let append_at = wire
            .find("APPEND \"Drafts\" (\\Draft \\Seen) {5}\r\n")
            .expect("append");
        let body_at = wire.find("\r\nhello\r\n").expect("body");
        assert!(append_at < body_at);
        assert!(wire.contains("a2 APPEND \"Drafts\" (\\Draft \\Seen) {5}\r\nhello\r\n"));
    }

    #[test]
    fn append_draft_does_not_send_the_body_without_continuation() {
        let (mut session, script) = logged_in(&["a2 NO [TRYCREATE] no mailbox"]);
        let err = session.append_draft(b"SECRET-DRAFT").unwrap_err();
        assert!(matches!(err, Error::Server(_)), "{err}");
        let wire = written_str(&script);
        assert!(wire.contains("APPEND \"Drafts\""));
        assert!(!wire.contains("SECRET-DRAFT"));

        let (mut session, script) = logged_in(&["a2 OK [APPENDUID 1 3] done"]);
        let err = session.append_draft(b"SECRET-DRAFT").unwrap_err();
        assert!(err.to_string().contains("continuation"), "{err}");
        assert!(!written_str(&script).contains("SECRET-DRAFT"));
    }

    #[test]
    fn append_draft_caps_at_2mib_and_returns_none_without_appenduid() {
        let (mut session, script) = logged_in(&[]);
        let len = script.written().len();
        let err = session
            .append_draft(&vec![b'a'; MAX_APPEND_BYTES + 1])
            .unwrap_err();
        assert!(err.to_string().contains("2MiB"), "{err}");
        assert_eq!(script.written().len(), len);
        assert_eq!(sync_literal_len("{2097152}"), Some(MAX_APPEND_BYTES));
        assert_eq!(sync_literal_len("{2097153}"), None);
        assert_eq!(sync_literal_len("{2+}"), None);

        let (mut session, _) = logged_in(&["+ go", "* OK [APPENDUID 1 7] side", "a2 OK done"]);
        assert_eq!(session.append_draft(b"ab").unwrap(), Some(7));
        let (mut session, _) = logged_in(&["+ go", "a2 OK saved"]);
        assert_eq!(session.append_draft(b"ab").unwrap(), None);
    }

    #[test]
    fn search_message_id_is_a_header_key() {
        let (mut session, script) = logged_in(&["* SEARCH 4 9", "a2 OK search"]);
        let uids = session
            .uid_search(&Search {
                message_id: Some("<abc@host>".to_string()),
                ..Search::default()
            })
            .unwrap();
        assert_eq!(uids, vec![4, 9]);
        assert!(
            written_str(&script).contains("a2 UID SEARCH HEADER MESSAGE-ID \"<abc@host>\"\r\n")
        );
        let len = script.written().len();
        let err = session
            .uid_search(&Search {
                message_id: Some("bad\nid".to_string()),
                ..Search::default()
            })
            .unwrap_err();
        assert!(matches!(err, Error::InvalidArgument(_)), "{err}");
        assert_eq!(script.written().len(), len);
    }

    #[test]
    fn fifty_uids_are_accepted_on_move() {
        let (mut session, script) = logged_in(&["a2 OK [READ-WRITE] selected", "a3 OK moved"]);
        session.select("Sent").unwrap();
        let uids: Vec<u32> = (1..=50).collect();
        let pairs = session.uid_move(&uids, "Folders/A/B").unwrap();
        assert!(pairs.is_empty());
        let wire = written_str(&script);
        assert!(wire.contains("a3 UID MOVE "));
        assert!(wire.contains(",50 \"Folders/A/B\"\r\n"));
        assert!(wire.contains("SELECT \"Sent\"\r\n"));
    }

    /// Sends "* OK progress" forever and never the tagged reply.
    struct Trickle {
        sent_greeting: bool,
    }
    impl std::io::Read for Trickle {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            let line: &[u8] = if self.sent_greeting { b"* OK still working\r\n" } else { b"* OK ready\r\n" };
            self.sent_greeting = true;
            let n = line.len().min(buf.len());
            buf[..n].copy_from_slice(&line[..n]);
            Ok(n)
        }
    }
    impl std::io::Write for Trickle {
        fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
            Ok(b.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn trickling_server_hits_the_deadline() {
        let mut conn = Conn::new(Trickle { sent_greeting: false });
        conn.read_greeting().unwrap();
        // Pretend the command started long ago.
        conn.deadline = Some(Instant::now());
        let err = conn.finish_command("a1", None).map(|_| ()).unwrap_err();
        assert!(matches!(err, Error::Io(ref e) if e.kind() == std::io::ErrorKind::TimedOut), "{err:?}");
    }
}
