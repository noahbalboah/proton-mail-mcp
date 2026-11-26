# proton-mail-mcp: module contract

A read-only MCP server (Rust, edition 2024, rustc 1.96) that lets one AI agent read a Proton Mail
mailbox through Proton Mail Bridge. It runs in a Docker container on a home server and is reached
only through `tailscale serve` (HTTPS, tailnet-only). The final crate is
`server/`.

## Ground rules for every module

- **Minimal dependencies.** The only third-party crates allowed in the final binary are
  `rustls` (=0.23.46, default-features = false, features ["ring", "std", "tls12"]),
  `rustls-pki-types` (=1.16.0) and `ring` (=0.17.14). Everything else is std. No dev-dependencies.
- **Hostile input.** IMAP responses and email content are attacker-controlled (anyone can email the
  user). Code must never panic on any input: no `unwrap`/`expect`/indexing that can fail on input
  data, no unchecked arithmetic on lengths, no recursion without a depth limit. Every buffer and
  count has a hard limit, listed below.
- **Read-only.** Nothing may change the mailbox. Nothing makes network connections except the IMAP
  client to the configured Bridge host.
- **No secrets in errors or logs.** Never include passwords, tokens or message content in error
  strings.
- `cargo clippy --all-targets -- -D warnings` and `cargo test` must pass. `#![forbid(unsafe_code)]`.
- Unit tests live in a `#[cfg(test)] mod tests` at the bottom of each file.

## json.rs

```rust
#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Number(String),            // the validated literal text, kept so JSON-RPC ids round-trip exactly
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>), // insertion order kept
}
pub fn parse(input: &[u8]) -> Result<Json, String>;
impl Json {
    pub fn get(&self, key: &str) -> Option<&Json>;   // Object lookup, else None
    pub fn as_str(&self) -> Option<&str>;
    pub fn as_bool(&self) -> Option<bool>;
    pub fn as_u64(&self) -> Option<u64>;              // Number with only digits (no sign, fraction, exponent), fits u64
    pub fn as_object(&self) -> Option<&[(String, Json)]>;
    pub fn str(s: impl Into<String>) -> Json;
    pub fn obj<const N: usize>(pairs: [(&str, Json); N]) -> Json;
}
impl std::fmt::Display for Json { /* compact serialization */ }
```

- Strict RFC 8259: UTF-8 only, no trailing commas, no comments, no leading zeros, no NaN/Infinity,
  exactly one value plus optional whitespace. Duplicate object keys are an error.
- String escapes incl. `\uXXXX` with surrogate pairs; lone surrogates are an error.
- Limits: input 1 MiB, nesting depth 64, string 1 MiB, 10_000 elements per array/object.
- Serialization escapes `"` `\` and every char below U+0020; everything else is emitted as UTF-8.

## mime.rs

```rust
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Headers { pub from: String, pub to: String, pub cc: String, pub date: String,
                     pub subject: String, pub message_id: String }
#[derive(Debug, Clone, PartialEq)]
pub struct Attachment { pub filename: String, pub content_type: String, pub size: usize }
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Message { pub headers: Headers, pub body: String, pub body_from_html: bool,
                     pub attachments: Vec<Attachment>, pub truncated: bool }

pub fn parse_headers(raw: &[u8]) -> Headers;                 // a header block (may lack the body)
pub fn parse_message(raw: &[u8], max_body_chars: usize) -> Message;
```

- Header unfolding (RFC 5322), case-insensitive names, first occurrence wins.
- RFC 2047 encoded words, B and Q, charsets utf-8, us-ascii, iso-8859-1/latin1, windows-1252
  (full table); unknown charsets decode lossily (invalid bytes become U+FFFD). Whitespace between
  adjacent encoded words is dropped.
- MIME: multipart/* (boundary from Content-Type), nesting depth limit 16, at most 200 parts.
  Transfer encodings base64 (ignore whitespace, tolerate missing padding), quoted-printable
  (soft line breaks), 7bit/8bit/binary. Charset from Content-Type for text parts, same set as above.
- Body choice: in multipart/alternative prefer text/plain, else text/html converted to text. Use
  the first suitable text part outside attachments. `body_from_html` says which.
- HTML to text: drop `<script>`, `<style>`, `<head>` and comments with their content; block tags
  (p, div, br, li, tr, h1-h6, table) become newlines; `<a href="x">label</a>` becomes `label (x)`;
  decode `&amp; &lt; &gt; &quot; &#39; &apos; &nbsp;` and numeric entities; collapse runs of blank
  lines to one. Never fetch anything.
- Attachments: parts with Content-Disposition attachment, or any non-text part with a filename,
  or message/rfc822. Filename from Content-Disposition `filename` / `filename*` (RFC 2231, incl.
  continuations) or Content-Type `name`, RFC 2047-decoded. `size` is the decoded byte size.
  Attachment contents are never returned.
- Output limits: body truncated to `max_body_chars` chars (`truncated = true`), each header field
  truncated to 2_000 chars, at most 100 attachments listed. Strip NUL and other C0 controls except
  `\n` and `\t` from all output strings; normalise `\r\n` to `\n`.

## http.rs

```rust
pub struct Request { pub method: String, pub path: String,
                     pub headers: Vec<(String, String)>, // names lowercased
                     pub body: Vec<u8> }
impl Request { pub fn header(&self, name: &str) -> Option<&str>; } // case-insensitive, first match
pub struct Response { pub status: u16, pub headers: Vec<(String, String)>, pub body: Vec<u8> }
impl Response { pub fn new(status: u16, content_type: &str, body: impl Into<Vec<u8>>) -> Self; }

pub fn read_request(stream: &mut impl std::io::Read) -> Result<Request, u16>; // Err = status to send
pub fn write_response(stream: &mut impl std::io::Write, resp: &Response) -> std::io::Result<()>;
pub fn serve<F>(addr: &str, max_connections: usize, handler: F) -> std::io::Result<()>
    where F: Fn(&Request) -> Response + Send + Sync + 'static;
```

- HTTP/1.1 and 1.0 only, one request per connection, always `Connection: close`, adds
  `Content-Length`. Thread per connection; read and write timeouts 30 s; when `max_connections`
  are busy, answer 503 at once and close.
- Limits: request line + headers 16 KiB (431), 100 headers (431), body 1 MiB (413).
- Body by `Content-Length` or `Transfer-Encoding: chunked` (decode it; chunk extensions and
  trailers tolerated). Both present, several differing Content-Length values, a non-numeric
  length, or any other transfer coding: 400. Unsupported version: 505. Bare LF line endings: 400.
- `Expect: 100-continue`: send `HTTP/1.1 100 Continue\r\n\r\n` before reading the body.
- A handler panic must not take down the server: catch it per connection and answer 500.
- Tests use in-memory readers/writers plus one real loopback round trip.

## imap.rs

A tiny IMAP4rev1 client. It may only ever send these commands: `CAPABILITY`, `STARTTLS`,
`LOGIN`, `LIST`, `EXAMINE`, `UID SEARCH`, `UID FETCH`, `NOOP`, `LOGOUT`. Enforce this in the
single function that writes commands (return an error otherwise) and test it. Never SELECT
(EXAMINE opens read-only), never STORE/COPY/MOVE/APPEND/EXPUNGE/DELETE/CREATE/RENAME/SUBSCRIBE.
Every body fetch uses `BODY.PEEK[...]` so `\Seen` is never set.

```rust
#[derive(Debug)]
pub enum Error { Io(std::io::Error), Protocol(String), Server(String), InvalidArgument(String) }
// Display + std::error::Error + From<io::Error>. Server = tagged NO/BAD (text truncated to 200 chars).

pub struct Conn<S> { /* stream + own read buffer; tag counter a1, a2, ... */ }
impl<S: Read + Write> Conn<S> {
    pub fn new(stream: S) -> Self;
    pub fn read_greeting(&mut self) -> Result<(), Error>;      // must be "* OK"; PREAUTH/BYE = error
    pub fn command(&mut self, cmd: &str) -> Result<Vec<Vec<u8>>, Error>; // returns untagged responses (raw, literals inline)
    pub fn into_inner(self) -> Result<S, Error>;              // Error if unread bytes are buffered (STARTTLS injection guard)
}

#[derive(Debug, Clone, PartialEq)]
pub struct Mailbox { pub name: String, pub noselect: bool }
#[derive(Debug, Clone, PartialEq)]
pub struct Fetched { pub uid: u32, pub flags: Vec<String>, pub size: Option<u64>, pub data: Option<Vec<u8>> }
#[derive(Debug, Clone, Default)]
pub struct Search { pub from: Option<String>, pub subject: Option<String>, pub text: Option<String>,
                    pub since: Option<String>, pub before: Option<String>, // "YYYY-MM-DD"
                    pub unseen: bool, pub max_uid: Option<u32> }      // only UIDs <= max_uid

pub struct Session<S> { /* Conn<S> */ }
impl<S: Read + Write> Session<S> {
    pub fn login(conn: Conn<S>, user: &str, password: &str) -> Result<Self, Error>;
    pub fn list_mailboxes(&mut self) -> Result<Vec<Mailbox>, Error>;          // LIST "" "*"
    pub fn examine(&mut self, mailbox: &str) -> Result<(), Error>;
    pub fn uid_search(&mut self, q: &Search) -> Result<Vec<u32>, Error>;       // sorted ascending
    pub fn fetch_headers(&mut self, uids: &[u32]) -> Result<Vec<Fetched>, Error>;
        // UID FETCH <set> (UID FLAGS RFC822.SIZE BODY.PEEK[HEADER.FIELDS (DATE FROM TO CC SUBJECT MESSAGE-ID)])
    pub fn fetch_message(&mut self, uid: u32, max_bytes: u32) -> Result<Option<Fetched>, Error>;
        // UID FETCH <uid> (UID FLAGS RFC822.SIZE BODY.PEEK[]<0.max_bytes>)
    pub fn logout(self);                                                        // best effort
}
```

- Response reading: a line ending in `{n}` (or `{n+}`) is followed by an n-byte literal, then the
  line continues. Limits: line 64 KiB, literal 8 MiB, one response 16 MiB, 100_000 untagged
  responses per command. A `+` continuation from the server is a protocol error.
- Parser for response data: atoms, quoted strings (with `\` escapes), literals, NIL, nested
  parenthesised lists (depth limit 16). An atom containing `[` runs to the matching `]` and may
  then have a `<...>` suffix (so `BODY[HEADER.FIELDS (DATE FROM)]` and `BODY[]<0>` are one atom).
  Match FETCH data items case-insensitively; the data value is the item after the
  `BODY[...]` key. Ignore unrelated untagged responses (EXISTS, RECENT, FLAGS, OK [...]).
- LIST names may be atoms, quoted strings or literals; `\Noselect` / `\NonExistent` set noselect.
- Quoting user input: mailbox names, search strings and login credentials go out as quoted strings
  with `\` and `"` escaped. Reject (InvalidArgument) anything with bytes outside printable ASCII
  0x20-0x7E. Dates must be valid `YYYY-MM-DD` and go out as `D-Mon-YYYY`. UID sets are built from
  numbers only; at most 200 UIDs per fetch.
- Tests: a scripted in-memory mock stream (canned server bytes in, captured client bytes out)
  covering greeting, login, LIST with literals, EXAMINE, SEARCH, FETCH with literals and odd
  spacing, tagged NO, overlong lines/literals, injection attempts (CR/LF/quotes in arguments),
  the command allowlist, and `into_inner` refusing buffered bytes.

## tls.rs

```rust
pub enum CertPin { Sha256([u8; 32]), Record(std::sync::Arc<std::sync::Mutex<Option<[u8; 32]>>>) }
pub type TlsStream = rustls::StreamOwned<rustls::ClientConnection, std::net::TcpStream>;
pub fn connect(host: &str, port: u16, pin: CertPin, timeout: std::time::Duration)
    -> Result<crate::imap::Conn<TlsStream>, crate::imap::Error>;
pub fn parse_fingerprint(s: &str) -> Result<[u8; 32], String>; // 64 hex chars, optional ':' separators, any case
pub fn fingerprint_hex(fp: &[u8; 32]) -> String;              // lowercase, colon-separated
```

- `connect`: TCP connect with timeout (try each resolved address), read/write timeouts 60 s,
  read greeting, `STARTTLS`, `into_inner` (refuse buffered bytes), then a rustls client using the
  ring provider, TLS 1.2 and 1.3, and a custom `ServerCertVerifier`:
  - `Sha256(pin)`: accept only if SHA-256 of the end-entity certificate DER equals the pin
    (constant-time compare, e.g. `ring::constant_time::verify_slices_are_equal` or a hand-written
    one). The server name and chain are ignored on purpose: Bridge uses a self-signed cert.
  - `Record(slot)`: store the fingerprint in the slot and accept (used only by the `fingerprint`
    subcommand that prints the cert hash and never logs in).
  - Handshake signatures are still verified with `rustls::crypto::verify_tls12_signature` /
    `verify_tls13_signature` and the provider's `signature_verification_algorithms`.
  - Server name: the host as a DNS name, or as an IP address if it parses as one.
- Return the `Conn` ready for `Session::login` (no greeting after STARTTLS).
- Tests: fingerprint parsing/formatting, and the verifier accepting the pinned DER and rejecting a
  different one (build the verifier directly with arbitrary DER bytes; no live TLS needed).
