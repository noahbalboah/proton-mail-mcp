//! Minimal HTTP/1.x request parsing and blocking single-thread-per-connection server.

#![allow(clippy::collapsible_if, clippy::type_complexity)]

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};
use std::thread;
use std::time::Duration;

const MAX_HEADER_BYTES: usize = 16 << 10;
const MAX_HEADERS: usize = 100;
const MAX_BODY: usize = 1 << 20;
const MAX_CHUNK_SIZE_LINE: usize = 4 << 10;
const IO_TIMEOUT: Duration = Duration::from_secs(30);

pub struct Request {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Request {
    pub fn header(&self, name: &str) -> Option<&str> {
        let lower = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| k == &lower)
            .map(|(_, v)| v.as_str())
    }
}

pub struct Response {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn new(status: u16, content_type: &str, body: impl Into<Vec<u8>>) -> Self {
        let body = body.into();
        let len = body.len();
        Response {
            status,
            headers: vec![
                ("content-type".to_string(), content_type.to_string()),
                ("content-length".to_string(), len.to_string()),
                ("connection".to_string(), "close".to_string()),
            ],
            body,
        }
    }
}

fn append_read(stream: &mut impl Read, buf: &mut Vec<u8>) -> Result<(), u16> {
    let mut chunk = [0u8; 4096];
    let n = stream.read(&mut chunk).map_err(|_| 400u16)?;
    if n == 0 {
        return Err(400);
    }
    buf.extend_from_slice(&chunk[..n]);
    Ok(())
}

fn bare_lf_in_headers(buf: &[u8]) -> bool {
    for (i, &b) in buf.iter().enumerate() {
        if b == b'\n' && i == 0 {
            return true;
        }
        if b == b'\n' {
            if buf.get(i.wrapping_sub(1)) != Some(&b'\r') {
                return true;
            }
        }
    }
    false
}

fn read_until_headers_end(buf: &mut Vec<u8>, stream: &mut impl Read) -> Result<usize, u16> {
    loop {
        if let Some(p) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
            let hdr = &buf[..p + 4];
            if bare_lf_in_headers(hdr) {
                return Err(400);
            }
            return Ok(p + 4);
        }
        if buf.len() > MAX_HEADER_BYTES {
            return Err(431);
        }
        if buf.windows(2).any(|w| w == b"\n\n") {
            return Err(400);
        }
        if bare_lf_in_headers(buf) {
            return Err(400);
        }
        append_read(stream, buf)?;
    }
}

fn parse_request_line(line: &str) -> Result<(String, String), u16> {
    let parts: Vec<&str> = line.split_whitespace().collect();
    if parts.len() != 3 {
        return Err(400);
    }
    let version = parts[2];
    if !version.eq("HTTP/1.1") && !version.eq("HTTP/1.0") {
        return Err(505);
    }
    Ok((parts[0].to_string(), parts[1].to_string()))
}

fn parse_header_lines(header_block: &str) -> Result<Vec<(String, String)>, u16> {
    let mut lines = header_block.split("\r\n");
    let _request_line = lines.next().ok_or(400u16)?;
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            return Err(400);
        };
        // RFC 9112: a field name is a token, with no whitespace before the colon. Accepting
        // "Content-Length : 5" is a classic request-smuggling gap, so refuse it.
        if name.is_empty() || !name.bytes().all(is_tchar) {
            return Err(400);
        }
        let name = name.to_ascii_lowercase();
        headers.push((name, value.trim_start().to_string()));
        if headers.len() > MAX_HEADERS {
            return Err(431);
        }
    }
    Ok(headers)
}

fn is_tchar(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

/// Digits only: `str::parse` and `from_str_radix` also accept a leading '+'.
fn parse_digits(s: &str, radix: u32) -> Result<usize, u16> {
    if s.is_empty() || !s.chars().all(|c| c.is_digit(radix)) {
        return Err(400);
    }
    usize::from_str_radix(s, radix).map_err(|_| 400)
}

fn has_te_chunked(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(k, v)| {
        k == "transfer-encoding"
            && v.to_ascii_lowercase()
                .split(',')
                .any(|p| p.trim() == "chunked")
    })
}

fn other_transfer_coding(headers: &[(String, String)]) -> bool {
    headers.iter().any(|(k, v)| {
        k == "transfer-encoding"
            && v.to_ascii_lowercase().split(',').any(|p| {
                let p = p.trim();
                !p.is_empty() && p != "chunked"
            })
    })
}

fn content_length(headers: &[(String, String)]) -> Result<Option<usize>, u16> {
    let cls: Vec<&str> = headers
        .iter()
        .filter(|(k, _)| k == "content-length")
        .map(|(_, v)| v.as_str())
        .collect();
    if cls.is_empty() {
        return Ok(None);
    }
    let first = cls[0];
    if cls.iter().any(|v| *v != first) {
        return Err(400);
    }
    Ok(Some(parse_digits(first.trim(), 10)?))
}

fn pull_more<R: Read>(pending: &mut Vec<u8>, stream: &mut R, scratch: &mut [u8; 4096]) -> Result<(), u16> {
    let n = stream.read(scratch).map_err(|_| 400u16)?;
    if n == 0 {
        return Err(400);
    }
    pending.extend_from_slice(&scratch[..n]);
    Ok(())
}

fn decode_chunked(stream: &mut impl Read, initial: Vec<u8>) -> Result<Vec<u8>, u16> {
    let mut body = Vec::new();
    let mut pending = initial;
    let mut scratch = [0u8; 4096];

    loop {
        loop {
            if pending.contains(&b'\n') {
                break;
            }
            if pending.len() > MAX_CHUNK_SIZE_LINE {
                return Err(400);
            }
            pull_more(&mut pending, stream, &mut scratch)?;
        }
        let nl = pending.iter().position(|&b| b == b'\n').ok_or(400u16)?;
        if nl > MAX_CHUNK_SIZE_LINE {
            return Err(400);
        }
        let line_bytes = pending[..nl].to_vec();
        pending.drain(..=nl);
        let line = if line_bytes.ends_with(b"\r") {
            std::str::from_utf8(&line_bytes[..line_bytes.len().saturating_sub(1)])
        } else {
            std::str::from_utf8(&line_bytes)
        }
        .map_err(|_| 400u16)?;
        let hex_part = line.split(';').next().unwrap_or("").trim();
        let size = parse_digits(hex_part, 16)?;
        if size == 0 {
            while pending.len() < 2 {
                if pull_more(&mut pending, stream, &mut scratch).is_err() {
                    break;
                }
            }
            if pending.len() >= 2 {
                pending.drain(..2.min(pending.len()));
            }
            break;
        }
        if body.len().saturating_add(size) > MAX_BODY {
            return Err(413);
        }
        while pending.len() < size.saturating_add(2) {
            pull_more(&mut pending, stream, &mut scratch)?;
        }
        body.extend_from_slice(&pending[..size]);
        pending.drain(..size);
        if pending.len() >= 2 && pending[0] == b'\r' && pending[1] == b'\n' {
            pending.drain(..2);
        } else if pending.first() == Some(&b'\n') {
            pending.drain(..1);
        }
    }
    Ok(body)
}

fn read_body(
    stream: &mut impl Read,
    headers: &[(String, String)],
    mut prefix: Vec<u8>,
) -> Result<Vec<u8>, u16> {
    let te = has_te_chunked(headers);
    let cl = content_length(headers)?;
    if te && cl.is_some() {
        return Err(400);
    }
    if other_transfer_coding(headers) {
        return Err(400);
    }
    if te {
        return decode_chunked(stream, prefix);
    }
    if let Some(len) = cl {
        if len > MAX_BODY {
            return Err(413);
        }
        while prefix.len() < len {
            let mut chunk = [0u8; 4096];
            let n = stream.read(&mut chunk).map_err(|_| 400u16)?;
            if n == 0 {
                break;
            }
            prefix.extend_from_slice(&chunk[..n]);
            if prefix.len() > MAX_BODY {
                return Err(413);
            }
        }
        if prefix.len() < len {
            return Err(400);
        }
        return Ok(prefix[..len].to_vec());
    }
    Ok(Vec::new())
}

fn read_request_parts(stream: &mut impl Read) -> Result<(String, String, Vec<(String, String)>, Vec<u8>), u16> {
    let mut buf = Vec::new();
    let header_total = read_until_headers_end(&mut buf, stream)?;
    if header_total > MAX_HEADER_BYTES {
        return Err(431);
    }
    let header_block = std::str::from_utf8(&buf[..header_total.saturating_sub(4)]).map_err(|_| 400u16)?;
    let request_line = header_block.split("\r\n").next().ok_or(400u16)?;
    let (method, path) = parse_request_line(request_line)?;
    let headers = parse_header_lines(header_block)?;
    let prefix = buf[header_total..].to_vec();
    let body = read_body(stream, &headers, prefix)?;
    Ok((method, path, headers, body))
}

pub fn read_request(stream: &mut impl Read) -> Result<Request, u16> {
    let (method, path, headers, body) = read_request_parts(stream)?;
    Ok(Request {
        method,
        path,
        headers,
        body,
    })
}

fn read_request_tcp(stream: &mut TcpStream) -> Result<Request, u16> {
    let mut buf = Vec::new();
    let header_total = read_until_headers_end(&mut buf, stream)?;
    if header_total > MAX_HEADER_BYTES {
        return Err(431);
    }
    let header_block = std::str::from_utf8(&buf[..header_total.saturating_sub(4)]).map_err(|_| 400u16)?;
    let request_line = header_block.split("\r\n").next().ok_or(400u16)?;
    let (method, path) = parse_request_line(request_line)?;
    let headers = parse_header_lines(header_block)?;
    let expect = headers.iter().any(|(k, v)| {
        k == "expect" && v.to_ascii_lowercase().contains("100-continue")
    });
    if expect {
        let _ = stream.write_all(b"HTTP/1.1 100 Continue\r\n\r\n");
    }
    let prefix = buf[header_total..].to_vec();
    let body = read_body(stream, &headers, prefix)?;
    Ok(Request {
        method,
        path,
        headers,
        body,
    })
}

pub fn write_response(stream: &mut impl Write, resp: &Response) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {} {}\r\n",
        resp.status,
        status_text(resp.status)
    )?;
    let mut wrote_connection = false;
    for (k, v) in &resp.headers {
        if k == "connection" {
            wrote_connection = true;
        }
        write!(stream, "{k}: {v}\r\n")?;
    }
    if !wrote_connection {
        stream.write_all(b"connection: close\r\n")?;
    }
    stream.write_all(b"\r\n")?;
    stream.write_all(&resp.body)?;
    stream.flush()
}

fn status_text(code: u16) -> &'static str {
    match code {
        100 => "Continue",
        200 => "OK",
        202 => "Accepted",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        413 => "Payload Too Large",
        415 => "Unsupported Media Type",
        431 => "Request Header Fields Too Large",
        500 => "Internal Server Error",
        503 => "Service Unavailable",
        505 => "HTTP Version Not Supported",
        _ => "Unknown",
    }
}

fn set_timeouts(stream: &TcpStream) {
    let _ = stream.set_read_timeout(Some(IO_TIMEOUT));
    let _ = stream.set_write_timeout(Some(IO_TIMEOUT));
}

pub fn serve<F>(addr: &str, max_connections: usize, handler: F) -> std::io::Result<()>
where
    F: Fn(&Request) -> Response + Send + Sync + 'static,
{
    let listener = TcpListener::bind(addr)?;
    let active = Arc::new(AtomicUsize::new(0));
    let handler = Arc::new(handler);

    for conn in listener.incoming() {
        let Ok(stream) = conn else { continue };
        let current = active.fetch_add(1, Ordering::SeqCst).saturating_add(1);
        if current > max_connections {
            active.fetch_sub(1, Ordering::SeqCst);
            set_timeouts(&stream);
            let mut stream = stream;
            let resp = Response::new(503, "text/plain", b"busy");
            let _ = write_response(&mut stream, &resp);
            continue;
        }

        let active2 = Arc::clone(&active);
        let handler2 = Arc::clone(&handler);
        thread::spawn(move || {
            set_timeouts(&stream);
            let mut stream = stream;
            match read_request_tcp(&mut stream) {
                Ok(req) => {
                    let resp = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        handler2(&req)
                    })) {
                        Ok(r) => r,
                        Err(_) => Response::new(500, "text/plain", b""),
                    };
                    let _ = write_response(&mut stream, &resp);
                }
                Err(status) => {
                    let resp = Response::new(status, "text/plain", b"");
                    let _ = write_response(&mut stream, &resp);
                }
            }
            active2.fetch_sub(1, Ordering::SeqCst);
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn status_of(raw: &[u8]) -> Result<Request, u16> {
        read_request(&mut Cursor::new(raw))
    }

    #[test]
    fn strict_header_names_and_lengths() {
        assert_eq!(status_of(b"POST / HTTP/1.1\r\nContent-Length : 1\r\n\r\nx").err(), Some(400));
        assert_eq!(status_of(b"POST / HTTP/1.1\r\n Content-Length: 1\r\n\r\nx").err(), Some(400));
        assert_eq!(status_of(b"POST / HTTP/1.1\r\nContent-Length: +1\r\n\r\nx").err(), Some(400));
        assert_eq!(status_of(b"POST / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\nxy").err(), Some(400));
        assert_eq!(
            status_of(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n+1\r\nx\r\n0\r\n\r\n").err(),
            Some(400)
        );
    }

    #[test]
    fn header_and_body_limits() {
        let mut big = b"GET / HTTP/1.1\r\nX: ".to_vec();
        big.extend(std::iter::repeat_n(b'a', MAX_HEADER_BYTES + 10));
        big.extend_from_slice(b"\r\n\r\n");
        assert_eq!(status_of(&big).err(), Some(431));
        let mut many = b"GET / HTTP/1.1\r\n".to_vec();
        for i in 0..=MAX_HEADERS {
            many.extend_from_slice(format!("X-{i}: 1\r\n").as_bytes());
        }
        many.extend_from_slice(b"\r\n");
        assert_eq!(status_of(&many).err(), Some(431));
        let huge = format!("POST / HTTP/1.1\r\nContent-Length: {}\r\n\r\n", MAX_BODY + 1);
        assert_eq!(status_of(huge.as_bytes()).err(), Some(413));
        // Small headers followed by a large body in the same reads must not be mistaken for 431.
        let mut ok = b"POST / HTTP/1.1\r\nContent-Length: 20000\r\n\r\n".to_vec();
        ok.extend(std::iter::repeat_n(b'b', 20000));
        assert_eq!(status_of(&ok).map(|r| r.body.len()).ok(), Some(20000));
    }

    #[test]
    fn response_uses_crlf_everywhere() {
        let mut out = Vec::new();
        let resp = Response { status: 202, headers: vec![], body: vec![] };
        write_response(&mut out, &resp).unwrap();
        assert_eq!(out, b"HTTP/1.1 202 Accepted\r\nconnection: close\r\n\r\n");
    }

    #[test]
    fn parse_simple_request() {
        let raw = b"GET /hello HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\nbody";
        let mut c = Cursor::new(&raw[..]);
        let req = read_request(&mut c).unwrap();
        assert_eq!(req.method, "GET");
        assert_eq!(req.path, "/hello");
        assert_eq!(req.body, b"body");
    }

    #[test]
    fn chunked_body() {
        let raw = b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
        let mut c = Cursor::new(&raw[..]);
        let req = read_request(&mut c).unwrap();
        assert_eq!(req.body, b"hello");
    }

    #[test]
    fn smuggling_cl_te() {
        let raw = b"POST / HTTP/1.1\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n";
        let mut c = Cursor::new(&raw[..]);
        assert!(matches!(read_request(&mut c), Err(400)));
    }

    #[test]
    fn conflicting_cl() {
        let raw = b"GET / HTTP/1.1\r\nContent-Length: 1\r\nContent-Length: 2\r\n\r\n";
        let mut c = Cursor::new(&raw[..]);
        assert!(matches!(read_request(&mut c), Err(400)));
    }

    #[test]
    fn bad_version() {
        let raw = b"GET / HTTP/2.0\r\n\r\n";
        let mut c = Cursor::new(&raw[..]);
        assert!(matches!(read_request(&mut c), Err(505)));
    }

    #[test]
    fn bare_lf_rejected() {
        let raw = b"GET / HTTP/1.1\nHost: x\n\n";
        let mut c = Cursor::new(&raw[..]);
        assert!(matches!(read_request(&mut c), Err(400)));
    }

    #[test]
    fn non_numeric_cl() {
        let raw = b"GET / HTTP/1.1\r\nContent-Length: abc\r\n\r\n";
        let mut c = Cursor::new(&raw[..]);
        assert!(matches!(read_request(&mut c), Err(400)));
    }

    #[test]
    fn handler_panic_500() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let addr = format!("127.0.0.1:{port}");
        drop(listener);
        let addr2 = addr.clone();
        let h = thread::spawn(move || {
            let _ = serve(&addr2, 4, |_req| panic!("boom"));
        });
        thread::sleep(Duration::from_millis(80));
        let mut stream = TcpStream::connect(&addr).unwrap();
        stream
            .write_all(b"GET / HTTP/1.1\r\nHost: t\r\n\r\n")
            .unwrap();
        stream.flush().unwrap();
        let text = drain_response(&mut stream);
        assert!(text.contains("500"));
        drop(h);
    }

    #[test]
    fn loopback_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let addr = format!("127.0.0.1:{port}");
        drop(listener);
        let addr2 = addr.clone();
        let server = thread::spawn(move || {
            let _ = serve(&addr2, 2, |req| Response::new(200, "text/plain", format!("path={}", req.path)));
        });
        thread::sleep(Duration::from_millis(80));
        let mut stream = TcpStream::connect(&addr).unwrap();
        stream
            .write_all(b"GET /test HTTP/1.1\r\nHost: t\r\n\r\n")
            .unwrap();
        stream.flush().unwrap();
        let text = drain_response(&mut stream);
        assert!(text.contains("path=/test"));
        drop(server);
    }

    #[test]
    fn expect_continue_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let addr = format!("127.0.0.1:{port}");
        drop(listener);
        let addr2 = addr.clone();
        let server = thread::spawn(move || {
            let _ = serve(&addr2, 2, |req| Response::new(200, "text/plain", req.body.clone()));
        });
        thread::sleep(Duration::from_millis(80));
        let mut stream = TcpStream::connect(&addr).unwrap();
        stream
            .write_all(
                b"POST / HTTP/1.1\r\nHost: t\r\nExpect: 100-continue\r\nContent-Length: 3\r\n\r\n",
            )
            .unwrap();
        stream.flush().unwrap();
        let mut interim = vec![0u8; 64];
        let n = stream.read(&mut interim).unwrap();
        assert!(String::from_utf8_lossy(&interim[..n]).contains("100"));
        stream.write_all(b"hey").unwrap();
        stream.flush().unwrap();
        let text = drain_response(&mut stream);
        assert!(text.contains("hey"));
        drop(server);
    }

    fn drain_response(stream: &mut TcpStream) -> String {
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            match stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(_) => break,
            }
        }
        String::from_utf8_lossy(&buf).into_owned()
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

        fn next(&mut self) -> u8 {
            let mut x = self.state;
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            self.state = x;
            (x & 0xff) as u8
        }
    }

    #[test]
    fn fuzz_read_request() {
        let mut rng = XorShift::new(42);
        for _ in 0..2000 {
            let len = (rng.next() as usize % 300) + 10;
            let mut buf = vec![0u8; len];
            for b in &mut buf {
                *b = rng.next();
            }
            let mut c = Cursor::new(&buf);
            let _ = read_request(&mut c);
            let t = rng.next() as usize % buf.len().max(1);
            let mut c2 = Cursor::new(&buf[..t.min(buf.len())]);
            let _ = read_request(&mut c2);
        }
    }

    struct Counting {
        inner: std::io::Cursor<Vec<u8>>,
        read: usize,
    }

    impl Read for Counting {
        fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> {
            let n = self.inner.read(b)?;
            self.read = self.read.saturating_add(n);
            Ok(n)
        }
    }

    #[test]
    fn chunk_size_line_bounded() {
        let mut raw = b"POST /mcp HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n".to_vec();
        raw.extend(std::iter::repeat_n(b'0', 8 << 20));
        let mut c = Counting {
            inner: std::io::Cursor::new(raw),
            read: 0,
        };
        let r = read_request(&mut c);
        assert!(r.is_err());
        assert!(c.read < 2 << 20);
    }
}