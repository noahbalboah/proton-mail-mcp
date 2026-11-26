//! MIME and RFC 5322 header / body parsing for email messages.

#![allow(clippy::collapsible_if)]

use crate::inflate::zlib_inflate;

pub use crate::security::Link;

const MAX_HEADER_FIELD: usize = 2_000;
const MAX_ATTACHMENTS: usize = 100;
const MAX_PARTS: usize = 200;
const MAX_NEST_DEPTH: usize = 16;
const MAX_HEADER_DECODE_INPUT: usize = 16 << 10;
const MAX_ENCODED_WORD_TEXT: usize = 256;
const MAX_ENTITY_BODY: usize = 32;
const HTML_INPUT_MARGIN: usize = 256;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Headers {
    pub from: String,
    pub to: String,
    pub cc: String,
    pub date: String,
    pub subject: String,
    pub message_id: String,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Attachment {
    pub filename: String,
    pub content_type: String,
    pub size: usize,
}

/// Decoded attachment payload returned by [`attachment`].
#[derive(Debug, Clone, PartialEq)]
pub struct AttachmentData {
    pub filename: String,
    pub content_type: String,
    pub bytes: Vec<u8>,
}

const MAX_PDF_INFLATED: usize = 50 * 1024 * 1024;
const MAX_PDF_STREAMS: usize = 2_000;

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Message {
    pub headers: Headers,
    pub body: String,
    pub body_from_html: bool,
    pub attachments: Vec<Attachment>,
    pub truncated: bool,
}

fn sanitize(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        let c = ch as u32;
        if ch == '\n' || ch == '\t' || c >= 0x20 {
            out.push(ch);
        }
    }
    out
}

fn truncate_field(s: String) -> String {
    let s = sanitize(&s);
    if s.len() <= MAX_HEADER_FIELD {
        return s;
    }
    s.chars().take(MAX_HEADER_FIELD).collect()
}

fn normalize_crlf_bytes(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut i = 0;
    while i < input.len() {
        if input[i] == b'\r' {
            out.push(b'\n');
            if i + 1 < input.len() && input[i + 1] == b'\n' {
                i += 2;
            } else {
                i += 1;
            }
        } else {
            out.push(input[i]);
            i += 1;
        }
    }
    out
}

fn decode_8bit_header_bytes(raw: &[u8]) -> String {
    let trimmed = raw.trim_ascii();
    match std::str::from_utf8(trimmed) {
        Ok(s) => s.to_string(),
        Err(_) => trimmed.iter().map(|&b| win1252_byte(b)).collect(),
    }
}

fn trim_ascii(bytes: &[u8]) -> &[u8] {
    let start = bytes
        .iter()
        .position(|&b| !b.is_ascii_whitespace())
        .unwrap_or(bytes.len());
    let end = bytes
        .iter()
        .rposition(|&b| !b.is_ascii_whitespace())
        .map_or(start, |i| i + 1);
    bytes.get(start..end).unwrap_or(&[])
}

fn win1252_byte(b: u8) -> char {
    const TABLE: &[char] = &[
        '\u{20AC}', '\u{0081}', '\u{201A}', '\u{0192}', '\u{201E}', '\u{2026}', '\u{2020}',
        '\u{2021}', '\u{02C6}', '\u{2030}', '\u{0160}', '\u{2039}', '\u{0152}', '\u{008D}',
        '\u{017D}', '\u{008F}', '\u{0090}', '\u{2018}', '\u{2019}', '\u{201C}', '\u{201D}',
        '\u{2022}', '\u{2013}', '\u{2014}', '\u{02DC}', '\u{2122}', '\u{0161}', '\u{203A}',
        '\u{0153}', '\u{009D}', '\u{017E}', '\u{0178}',
    ];
    if b < 0x80 {
        char::from(b)
    } else if (0x80..=0x9F).contains(&b) {
        TABLE[(b - 0x80) as usize]
    } else {
        char::from(b)
    }
}

fn decode_bytes_lossy(data: &[u8], charset: &str) -> String {
    let cs = charset.trim().to_ascii_lowercase();
    let cs = cs.split(';').next().unwrap_or(&cs).trim();
    if cs == "utf-8" || cs == "us-ascii" || cs.is_empty() {
        String::from_utf8_lossy(data).into_owned()
    } else if cs == "iso-8859-1" || cs == "latin1" || cs == "iso_8859-1" {
        data.iter().map(|&b| char::from(b)).collect()
    } else if cs == "windows-1252" || cs == "cp1252" {
        data.iter().map(|&b| win1252_byte(b)).collect()
    } else {
        String::from_utf8_lossy(data).into_owned()
    }
}

fn qp_decode(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < data.len() {
        if data[i] == b'=' {
            if i + 1 < data.len() && data[i + 1] == b'\r' {
                if i + 2 < data.len() && data[i + 2] == b'\n' {
                    i += 3;
                    continue;
                }
            }
            if i + 1 < data.len() && data[i + 1] == b'\n' {
                i += 2;
                continue;
            }
            if i + 2 < data.len() {
                let hi = hex_nibble(data[i + 1]);
                let lo = hex_nibble(data[i + 2]);
                if let (Some(h), Some(l)) = (hi, lo) {
                    out.push((h << 4) | l);
                    i += 3;
                    continue;
                }
            }
        }
        out.push(data[i]);
        i += 1;
    }
    out
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn b64_decode(data: &[u8]) -> Vec<u8> {
    const TABLE: [i8; 256] = {
        let mut t = [-1i8; 256];
        let mut i = 0u8;
        while i < 26 {
            t[(b'A' + i) as usize] = i as i8;
            i += 1;
        }
        i = 0;
        while i < 26 {
            t[(b'a' + i) as usize] = 26 + i as i8;
            i += 1;
        }
        i = 0;
        while i < 10 {
            t[(b'0' + i) as usize] = 52 + i as i8;
            i += 1;
        }
        t[b'+' as usize] = 62;
        t[b'/' as usize] = 63;
        t
    };
    let bytes: Vec<u8> = data
        .iter()
        .copied()
        .filter(|b| !b.is_ascii_whitespace())
        .collect();
    let mut out = Vec::new();
    let mut buf = 0u32;
    let mut bits = 0u32;
    let mut pad = 0usize;
    for &b in &bytes {
        if b == b'=' {
            pad += 1;
            continue;
        }
        let v = TABLE.get(b as usize).copied().unwrap_or(-1);
        if v < 0 {
            continue;
        }
        buf = (buf << 6) | v as u32;
        bits = bits.saturating_add(6);
        if bits >= 8 {
            bits = bits.saturating_sub(8);
            out.push((buf >> bits) as u8);
            buf &= (1 << bits) - 1;
        }
    }
    let _ = pad;
    out
}

fn unfold_header_block_fixed(raw: &[u8]) -> Vec<Vec<u8>> {
    let norm = normalize_crlf_bytes(raw);
    let mut result_lines: Vec<Vec<u8>> = Vec::new();
    for line in norm.split(|&b| b == b'\n') {
        if let Some(last) = result_lines.last_mut() {
            if line.first().is_some_and(|b| *b == b' ' || *b == b'\t') {
                last.push(b' ');
                last.extend_from_slice(trim_ascii(line));
                continue;
            }
        }
        result_lines.push(line.to_vec());
    }
    result_lines
}

fn decode_rfc2047_word(encoded: &str) -> Option<String> {
    let enc = encoded.trim();
    if !enc.starts_with("=?") || !enc.ends_with("?=") || enc.len() < 5 {
        return None;
    }
    let inner = &enc[2..enc.len().saturating_sub(2)];
    let segs: Vec<&str> = inner.split('?').collect();
    if segs.len() != 3 {
        return None;
    }
    let charset = segs[0];
    let mode = segs[1];
    let data = segs[2];
    let bytes = if mode.eq_ignore_ascii_case("B") {
        b64_decode(data.as_bytes())
    } else if mode.eq_ignore_ascii_case("Q") {
        decode_q_encoding(data)
    } else {
        return None;
    };
    Some(decode_bytes_lossy(&bytes, charset))
}

fn decode_q_encoding(s: &str) -> Vec<u8> {
    let mut out = Vec::new();
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'_' {
            out.push(b' ');
            i += 1;
        } else if bytes[i] == b'=' {
            if i + 2 < bytes.len() {
                if let (Some(h), Some(l)) = (hex_nibble(bytes[i + 1]), hex_nibble(bytes[i + 2])) {
                    out.push((h << 4) | l);
                    i += 3;
                    continue;
                }
            }
            out.push(bytes[i]);
            i += 1;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    out
}

/// Length of the encoded word at the start of `s` (`=?charset?X?text?=`), if it is one. The end
/// is the first `?=` after the encoding letter, not the first in the string: Q text such as
/// `=?utf-8?Q?=C3=A9?=` contains `?=` right after the `Q`.
fn encoded_word_len(s: &str) -> Option<usize> {
    let rest = s.strip_prefix("=?")?;
    let charset_len = rest.find('?')?;
    let after_charset = rest.get(charset_len.checked_add(1)?..)?;
    let mut chars = after_charset.chars();
    let enc = chars.next()?;
    if !matches!(enc, 'B' | 'b' | 'Q' | 'q') || chars.next()? != '?' {
        return None;
    }
    let text_start = 2usize.checked_add(charset_len)?.checked_add(3)?;
    let tail = s.get(text_start..)?;
    let scan = tail.len().min(MAX_ENCODED_WORD_TEXT);
    let prefix = tail.get(..scan)?;
    let text_len = prefix.find("?=")?;
    text_start.checked_add(text_len)?.checked_add(2)
}

/// Decode every encoded word inside one whitespace-free token, leaving other text as is.
/// Returns the text and whether the whole token was a single encoded word.
fn decode_token(tok: &str) -> (String, bool) {
    let mut out = String::new();
    let mut rest = tok;
    let mut whole = false;
    while let Some(start) = rest.find("=?") {
        out.push_str(rest.get(..start).unwrap_or(""));
        let tail = rest.get(start..).unwrap_or("");
        match encoded_word_len(tail).and_then(|len| Some((len, decode_rfc2047_word(tail.get(..len)?)?))) {
            Some((len, decoded)) => {
                whole = start == 0 && len == tok.len();
                out.push_str(&decoded);
                rest = tail.get(len..).unwrap_or("");
            }
            None => {
                out.push_str("=?");
                rest = tail.get(2..).unwrap_or("");
            }
        }
    }
    out.push_str(rest);
    (out, whole)
}

fn decode_header_value(raw: &str) -> String {
    let raw = if raw.len() > MAX_HEADER_DECODE_INPUT {
        &raw[..MAX_HEADER_DECODE_INPUT]
    } else {
        raw
    };
    let mut out = String::new();
    let mut rest = raw.trim();
    let mut prev_was_word = false;
    while !rest.is_empty() {
        let tok_start = rest.len() - rest.trim_start().len();
        let ws = rest.get(..tok_start).unwrap_or("");
        rest = rest.get(tok_start..).unwrap_or("");
        let tok_len = rest.find(char::is_whitespace).unwrap_or(rest.len());
        let tok = rest.get(..tok_len).unwrap_or("");
        rest = rest.get(tok_len..).unwrap_or("");
        let (text, is_word) = decode_token(tok);
        // RFC 2047 6.2: whitespace between two adjacent encoded words is dropped; whitespace
        // next to ordinary text is kept.
        if !(prev_was_word && is_word) {
            out.push_str(ws);
        }
        out.push_str(&text);
        prev_was_word = is_word;
    }
    sanitize(&out)
}

fn header_map(lines: &[Vec<u8>]) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for line in lines {
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        let name = trim_ascii(&line[..colon]);
        let key = String::from_utf8_lossy(name).trim().to_ascii_lowercase();
        let value = decode_8bit_header_bytes(&line[colon + 1..]);
        map.entry(key).or_insert_with(|| decode_header_value(&value));
    }
    map
}

pub fn parse_headers(raw: &[u8]) -> Headers {
    let lines = unfold_header_block_fixed(raw);
    let map = header_map(&lines);
    let get = |k: &str| -> String {
        map.get(k)
            .map(|v| truncate_field(v.clone()))
            .unwrap_or_default()
    };
    Headers {
        from: get("from"),
        to: get("to"),
        cc: get("cc"),
        date: get("date"),
        subject: get("subject"),
        message_id: get("message-id"),
    }
}

/// Header block only (bytes before the first blank line).
pub fn header_section(raw: &[u8]) -> &[u8] {
    if let Some(pos) = find_subslice(raw, b"\r\n\r\n") {
        return raw.get(..pos).unwrap_or(raw);
    }
    if let Some(pos) = find_subslice(raw, b"\n\n") {
        return raw.get(..pos).unwrap_or(raw);
    }
    raw
}

fn split_headers_body(raw: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let sep = b"\r\n\r\n";
    if let Some(pos) = find_subslice(raw, sep) {
        return (raw[..pos].to_vec(), raw[pos + 4..].to_vec());
    }
  let sep2 = b"\n\n";
    if let Some(pos) = find_subslice(raw, sep2) {
        return (raw[..pos].to_vec(), raw[pos + 2..].to_vec());
    }
    (raw.to_vec(), Vec::new())
}

fn find_subslice(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len())
        .position(|w| w == needle)
}

fn get_param<'a>(params: &'a str, name: &str) -> Option<&'a str> {
    let lower = params.to_ascii_lowercase();
    let search = format!("{name}=");
    if let Some(pos) = lower.find(&search) {
        let rest = &params[pos + search.len()..];
        let rest = rest.trim_start();
        if let Some(stripped) = rest.strip_prefix('"') {
            let end = stripped.find('"')?;
            return Some(&stripped[..end]);
        }
        let end = rest
            .find(|c: char| c == ';' || c.is_whitespace())
            .unwrap_or(rest.len());
        return Some(rest[..end].trim());
    }
    None
}

fn parse_boundary(ct: &str) -> Option<String> {
    get_param(ct, "boundary").map(|b| b.to_string())
}

fn decode_body_part(data: &[u8], encoding: &str, charset: &str) -> String {
    let enc = encoding.trim().to_ascii_lowercase();
    let decoded = match enc.as_str() {
        "base64" => b64_decode(data),
        "quoted-printable" => qp_decode(data),
        "7bit" | "8bit" | "binary" | "" => data.to_vec(),
        _ => data.to_vec(),
    };
    decode_bytes_lossy(&decoded, charset)
}

fn cap_html_input(html: &str, max_body_chars: usize) -> &str {
    let max_bytes = max_body_chars
        .saturating_mul(4)
        .saturating_add(HTML_INPUT_MARGIN);
    if html.len() <= max_bytes {
        return html;
    }
    let mut end = max_bytes;
    while end > 0 && !html.is_char_boundary(end) {
        end -= 1;
    }
    &html[..end]
}

fn block_tag_newline(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "p" | "div" | "br" | "li" | "tr" | "h1" | "h2" | "h3" | "h4" | "h5" | "h6" | "table"
    )
}

fn find_ci(hay: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() || hay.len() < needle.len() {
        return None;
    }
    hay.windows(needle.len())
        .position(|w| w.eq_ignore_ascii_case(needle))
}

enum HtmlSkip {
    Comment,
    Script,
    Style,
    Head,
}

fn push_text_char(out: &mut String, html: &str, i: &mut usize) {
    let b = html.as_bytes();
    if *i >= b.len() {
        return;
    }
    if b[*i] == b'&' {
        if try_push_entity(out, html, i) {
            return;
        }
    }
    let Some(ch) = html[*i..].chars().next() else {
        *i += 1;
        return;
    };
    out.push(ch);
    *i += ch.len_utf8();
}

fn try_push_entity(out: &mut String, html: &str, i: &mut usize) -> bool {
    let b = html.as_bytes();
    if *i >= b.len() || b[*i] != b'&' {
        return false;
    }
    let rem = b.len().saturating_sub(*i + 1);
    let lim = rem.min(MAX_ENTITY_BODY);
    let Some(semi) = memchr(b';', &b[*i + 1..][..lim]) else {
        return false;
    };
    let ent = html.get(*i + 1..*i + 1 + semi).unwrap_or("");
    let decoded = decode_entity_name(ent);
    if let Some(ch) = decoded {
        out.push(ch);
        *i += semi + 2;
        return true;
    }
    if let Some(s) = decoded_str(ent) {
        out.push_str(s);
        *i += semi + 2;
        return true;
    }
    false
}

fn decoded_str(ent: &str) -> Option<&'static str> {
    match ent {
        "amp" => Some("&"),
        "lt" => Some("<"),
        "gt" => Some(">"),
        "quot" => Some("\""),
        "apos" | "#39" => Some("'"),
        "nbsp" => Some("\u{00a0}"),
        _ => None,
    }
}

fn decode_entity_name(ent: &str) -> Option<char> {
    if let Some(s) = decoded_str(ent) {
        return s.chars().next();
    }
    if let Some(rest) = ent.strip_prefix('#') {
        let num = if let Some(hex) = rest.strip_prefix(['x', 'X']) {
            u32::from_str_radix(hex, 16).ok()
        } else if !rest.is_empty() {
            rest.parse().ok()
        } else {
            None
        };
        return num.and_then(char::from_u32);
    }
    None
}

fn html_to_text_limited(html: &str, max_body_chars: usize) -> String {
    let html = cap_html_input(html, max_body_chars);
    let bytes = html.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;
    let mut out = String::new();
    let mut skip: Option<HtmlSkip> = None;

    while i < len {
        if let Some(ref mode) = skip {
            match *mode {
                HtmlSkip::Comment => {
                    if let Some(p) = find_ci(&bytes[i..], b"-->") {
                        i += p + 3;
                        skip = None;
                    } else {
                        i = len;
                    }
                    continue;
                }
                HtmlSkip::Script => {
                    if let Some(p) = find_ci(&bytes[i..], b"</script>") {
                        i += p + 9;
                        skip = None;
                    } else {
                        i = len;
                    }
                    continue;
                }
                HtmlSkip::Style => {
                    if let Some(p) = find_ci(&bytes[i..], b"</style>") {
                        i += p + 8;
                        skip = None;
                    } else {
                        i = len;
                    }
                    continue;
                }
                HtmlSkip::Head => {
                    if let Some(p) = find_ci(&bytes[i..], b"</head>") {
                        i += p + 7;
                        skip = None;
                    } else {
                        i = len;
                    }
                    continue;
                }
            }
        }

        if bytes[i] == b'<' {
            if bytes[i..].starts_with(b"<!--") {
                i += 4;
                skip = Some(HtmlSkip::Comment);
                continue;
            }
            let Some(gt_off) = memchr(b'>', &bytes[i..]) else {
                i = len;
                continue;
            };
            let tag_slice = &html[i + 1..i + gt_off];
            let trimmed = tag_slice.trim_start();
            let is_close = trimmed.starts_with('/');
            let name = trimmed
                .trim_start_matches('/')
                .split_whitespace()
                .next()
                .unwrap_or("");
            if !is_close && name.eq_ignore_ascii_case("script") {
                i += gt_off + 1;
                skip = Some(HtmlSkip::Script);
                continue;
            }
            if !is_close && name.eq_ignore_ascii_case("style") {
                i += gt_off + 1;
                skip = Some(HtmlSkip::Style);
                continue;
            }
            if !is_close && name.eq_ignore_ascii_case("head") {
                i += gt_off + 1;
                skip = Some(HtmlSkip::Head);
                continue;
            }
            if !is_close && name.eq_ignore_ascii_case("a") {
                if let Some(href) = extract_attr(tag_slice, "href") {
                    let content_start = i + gt_off + 1;
                    if let Some(end_off) = find_ci(&bytes[content_start..], b"</a>") {
                        let label = &html[content_start..content_start + end_off];
                        let plain = strip_tags_quick(label);
                        for ch in plain.chars() {
                            out.push(ch);
                        }
                        out.push_str(" (");
                        out.push_str(&href);
                        out.push(')');
                        i = content_start + end_off + 4;
                        continue;
                    }
                }
            }
            if block_tag_newline(name) {
                out.push('\n');
            }
            i += gt_off + 1;
            continue;
        }

        push_text_char(&mut out, html, &mut i);
    }

    collapse_blank_lines(&out)
}

fn memchr(needle: u8, hay: &[u8]) -> Option<usize> {
    hay.iter().position(|&b| b == needle)
}

fn extract_attr(tag: &str, name: &str) -> Option<String> {
    let lower = tag.to_ascii_lowercase();
    let search = format!("{name}=");
    let pos = lower.find(&search)?;
    let rest = &tag[pos + search.len()..];
    if let Some(stripped) = rest.strip_prefix('"') {
        let end = stripped.find('"')?;
        return Some(stripped[..end].to_string());
    }
    if let Some(stripped) = rest.strip_prefix('\'') {
        let end = stripped.find('\'')?;
        return Some(stripped[..end].to_string());
    }
    let end = rest.find([' ', '>']).unwrap_or(rest.len());
    Some(rest[..end].to_string())
}

fn strip_tags_quick(s: &str) -> String {
    let mut out = String::new();
    let mut in_tag = false;
    for ch in s.chars() {
        if ch == '<' {
            in_tag = true;
        } else if ch == '>' {
            in_tag = false;
        } else if !in_tag {
            out.push(ch);
        }
    }
    out
}

fn collapse_blank_lines(s: &str) -> String {
    let mut out = String::new();
    let mut prev_blank = false;
    for line in s.lines() {
        let trimmed = line.trim_end();
        let blank = trimmed.is_empty();
        if blank {
            if !prev_blank {
                out.push('\n');
            }
            prev_blank = true;
        } else {
            out.push_str(trimmed);
            out.push('\n');
            prev_blank = false;
        }
    }
    out.trim().to_string()
}

fn parse_part_headers(hblock: &[u8]) -> std::collections::HashMap<String, String> {
    header_map(&unfold_header_block_fixed(hblock))
}

fn split_multipart(body: &[u8], boundary: &str) -> Vec<Vec<u8>> {
    let delim = format!("--{boundary}");
    let end = format!("--{boundary}--");
    let norm = normalize_crlf_bytes(body);
    let mut parts = Vec::new();
    let mut current: Vec<u8> = Vec::new();
    let mut in_part = false;
    for line in norm.split(|&b| b == b'\n') {
        if line == delim.as_bytes() {
            if in_part {
                parts.push(std::mem::take(&mut current));
            }
            in_part = true;
        } else if line == end.as_bytes() {
            if in_part && !current.is_empty() {
                parts.push(std::mem::take(&mut current));
            }
            break;
        } else if in_part {
            if !current.is_empty() {
                current.push(b'\n');
            }
            current.extend_from_slice(line);
        }
    }
    if parts.is_empty() && !body.is_empty() {
        parts.push(body.to_vec());
    }
    parts
}

fn part_content_type(h: &std::collections::HashMap<String, String>) -> String {
    h.get("content-type")
        .cloned()
        .unwrap_or_else(|| "text/plain".to_string())
}

fn part_encoding(h: &std::collections::HashMap<String, String>) -> String {
    h.get("content-transfer-encoding")
        .cloned()
        .unwrap_or_default()
}

fn is_attachment(h: &std::collections::HashMap<String, String>) -> bool {
    if let Some(cd) = h.get("content-disposition") {
        if cd.to_ascii_lowercase().contains("attachment") {
            return true;
        }
    }
    let ct = part_content_type(h).to_ascii_lowercase();
    if ct.starts_with("message/rfc822") {
        return true;
    }
    if let Some(cd) = h.get("content-disposition") {
        if get_param(cd, "filename").is_some() {
            return !ct.starts_with("text/");
        }
    }
    get_param(&ct, "name").is_some_and(|_| !ct.starts_with("text/"))
}

fn filename_from_part(h: &std::collections::HashMap<String, String>) -> String {
    if let Some(cd) = h.get("content-disposition") {
        if let Some(f) = get_param(cd, "filename*") {
            return decode_rfc2231_filename(f);
        }
        if let Some(f) = get_param(cd, "filename") {
            return decode_header_value(f);
        }
    }
    let ct = part_content_type(h);
    if let Some(n) = get_param(&ct, "name") {
        return decode_header_value(n);
    }
    String::new()
}

fn decode_rfc2231_filename(s: &str) -> String {
    let mut i = 0;
    let bytes = s.as_bytes();
    while i < bytes.len() && bytes[i] != b'\'' {
        i += 1;
    }
    if i >= bytes.len() {
        return decode_header_value(s);
    }
    i += 1;
    let mut lang_end = i;
    while lang_end < bytes.len() && bytes[lang_end] != b'\'' {
        lang_end += 1;
    }
    let charset = if i > 0 {
        String::from_utf8_lossy(&bytes[..i.saturating_sub(1)])
            .to_ascii_lowercase()
    } else {
        "utf-8".to_string()
    };
    let payload = if lang_end < bytes.len() {
        &bytes[lang_end + 1..]
    } else {
        &bytes[..0]
    };
    // percent-decode
    let mut out = Vec::new();
    let mut j = 0;
    while j < payload.len() {
        if payload[j] == b'%' && j + 2 < payload.len() {
            if let (Some(h), Some(l)) = (hex_nibble(payload[j + 1]), hex_nibble(payload[j + 2])) {
                out.push((h << 4) | l);
                j += 3;
                continue;
            }
        }
        out.push(payload[j]);
        j += 1;
    }
    decode_bytes_lossy(&out, &charset)
}

struct BodyChoice {
    plain: Option<String>,
    html: Option<String>,
}

fn charset_from_ct(ct: &str) -> String {
    get_param(ct, "charset")
        .unwrap_or("utf-8")
        .to_string()
}

struct InternalAttachment {
    filename: String,
    content_type: String,
    bytes: Vec<u8>,
}

fn collect_body(
    header_block: &[u8],
    body: &[u8],
    depth: usize,
    part_count: &mut usize,
    attachments: &mut Vec<InternalAttachment>,
    max_body_chars: usize,
) -> BodyChoice {
    let mut choice = BodyChoice {
        plain: None,
        html: None,
    };
    if depth > MAX_NEST_DEPTH {
        return choice;
    }
    let h = parse_part_headers(header_block);
    let ct = part_content_type(&h);
    let ct_lower = ct.to_ascii_lowercase();

    if is_attachment(&h) && *part_count < MAX_PARTS {
        *part_count = part_count.saturating_add(1);
        if attachments.len() < MAX_ATTACHMENTS {
            let enc = part_encoding(&h);
            let decoded = match enc.to_ascii_lowercase().as_str() {
                "base64" => b64_decode(body),
                "quoted-printable" => qp_decode(body),
                _ => body.to_vec(),
            };
            attachments.push(InternalAttachment {
                filename: truncate_field(filename_from_part(&h)),
                content_type: truncate_field(ct),
                bytes: decoded,
            });
        }
        return choice;
    }

    *part_count = part_count.saturating_add(1);
    if *part_count > MAX_PARTS {
        return choice;
    }

    if ct_lower.starts_with("multipart/") {
        if let Some(boundary) = parse_boundary(&ct) {
            for part in split_multipart(body, &boundary) {
                if *part_count > MAX_PARTS {
                    break;
                }
                let (ph, pb) = split_headers_body(&part);
                let sub =
                    collect_body(&ph, &pb, depth.saturating_add(1), part_count, attachments, max_body_chars);
                merge_choice(&mut choice, sub, &ct_lower);
            }
        }
        return choice;
    }

    let charset = charset_from_ct(&ct);
    let text = decode_body_part(body, &part_encoding(&h), &charset);
    let text = sanitize(&text);

    if ct_lower.starts_with("text/html") {
        choice.html = Some(html_to_text_limited(&text, max_body_chars));
    } else if ct_lower.starts_with("text/") {
        choice.plain = Some(text);
    }
    choice
}

fn merge_choice(dest: &mut BodyChoice, sub: BodyChoice, _parent_ct: &str) {
    if dest.plain.is_none() {
        dest.plain = sub.plain;
    }
    if dest.html.is_none() {
        dest.html = sub.html;
    }
}

fn walk_parts(raw: &[u8], max_body_chars: usize) -> (Headers, BodyChoice, Vec<InternalAttachment>) {
    let (hdr_bytes, body_bytes) = split_headers_body(raw);
    let headers = parse_headers(&hdr_bytes);
    let mut attachments = Vec::new();
    let mut part_count = 0usize;
    let choice = collect_body(
        &hdr_bytes,
        &body_bytes,
        0,
        &mut part_count,
        &mut attachments,
        max_body_chars,
    );
    (headers, choice, attachments)
}

pub fn parse_message(raw: &[u8], max_body_chars: usize) -> Message {
    let (headers, choice, internal) = walk_parts(raw, max_body_chars);
    let attachments: Vec<Attachment> = internal
        .iter()
        .map(|a| Attachment {
            filename: a.filename.clone(),
            content_type: a.content_type.clone(),
            size: a.bytes.len(),
        })
        .collect();
    let (body, body_from_html) = if let Some(p) = choice.plain {
        (p, false)
    } else if let Some(h) = choice.html {
        (h, true)
    } else {
        (String::new(), false)
    };
    let body = sanitize(&body);
    let (body, truncated) = if body.chars().count() > max_body_chars {
        (
            body.chars().take(max_body_chars).collect(),
            true,
        )
    } else {
        (body, false)
    };
    Message {
        headers,
        body,
        body_from_html,
        attachments,
        truncated,
    }
}

fn collect_html_raw(
    header_block: &[u8],
    body: &[u8],
    depth: usize,
    part_count: &mut usize,
    out: &mut Vec<String>,
) {
    if depth > MAX_NEST_DEPTH || out.len() >= MAX_PARTS {
        return;
    }
    let h = parse_part_headers(header_block);
    let ct = part_content_type(&h);
    let ct_lower = ct.to_ascii_lowercase();

    if is_attachment(&h) {
        *part_count = part_count.saturating_add(1);
        return;
    }

    *part_count = part_count.saturating_add(1);
    if *part_count > MAX_PARTS {
        return;
    }

    if ct_lower.starts_with("multipart/") {
        if let Some(boundary) = parse_boundary(&ct) {
            for part in split_multipart(body, &boundary) {
                if *part_count > MAX_PARTS {
                    break;
                }
                let (ph, pb) = split_headers_body(&part);
                collect_html_raw(&ph, &pb, depth.saturating_add(1), part_count, out);
            }
        }
        return;
    }

    if ct_lower.starts_with("text/html") {
        let charset = charset_from_ct(&ct);
        let text = decode_body_part(body, &part_encoding(&h), &charset);
        out.push(text);
    }
}

/// Collect up to `max` visible-text / href pairs from HTML parts of `raw_message`.
pub fn html_links(raw_message: &[u8], max: usize) -> Vec<Link> {
    let max = max.min(512);
    let (hdr_bytes, body_bytes) = split_headers_body(raw_message);
    let mut htmls = Vec::new();
    let mut part_count = 0usize;
    collect_html_raw(&hdr_bytes, &body_bytes, 0, &mut part_count, &mut htmls);
    let mut links = Vec::new();
    for html in htmls {
        if links.len() >= max {
            break;
        }
        extract_html_links(html.as_str(), max.saturating_sub(links.len()), &mut links);
    }
    links
}

fn collapse_ws(s: &str) -> String {
    let mut out = String::new();
    let mut prev_space = false;
    for ch in s.chars() {
        if ch.is_whitespace() {
            if !prev_space {
                out.push(' ');
                prev_space = true;
            }
        } else {
            out.push(ch);
            prev_space = false;
        }
    }
    out.trim().to_string()
}

fn anchor_visible_text(html: &str) -> String {
    let bytes = html.as_bytes();
    let mut i = 0usize;
    let mut out = String::new();
    let len = bytes.len();
    while i < len {
        if bytes[i] == b'<' {
            if let Some(gt) = memchr(b'>', &bytes[i..]) {
                i += gt + 1;
            } else {
                break;
            }
            continue;
        }
        push_text_char(&mut out, html, &mut i);
    }
    collapse_ws(&out)
}

fn extract_html_links(html: &str, room: usize, out: &mut Vec<Link>) {
    if room == 0 {
        return;
    }
    let html = cap_html_input(html, 500_000);
    let bytes = html.as_bytes();
    let len = bytes.len();
    let mut i = 0usize;
    let mut skip: Option<HtmlSkip> = None;

    while i < len && out.len() < room {
        if let Some(ref mode) = skip {
            match *mode {
                HtmlSkip::Comment => {
                    if let Some(p) = find_ci(&bytes[i..], b"-->") {
                        i += p + 3;
                        skip = None;
                    } else {
                        break;
                    }
                    continue;
                }
                HtmlSkip::Script => {
                    if let Some(p) = find_ci(&bytes[i..], b"</script>") {
                        i += p + 9;
                        skip = None;
                    } else {
                        break;
                    }
                    continue;
                }
                HtmlSkip::Style => {
                    if let Some(p) = find_ci(&bytes[i..], b"</style>") {
                        i += p + 8;
                        skip = None;
                    } else {
                        break;
                    }
                    continue;
                }
                HtmlSkip::Head => {
                    if let Some(p) = find_ci(&bytes[i..], b"</head>") {
                        i += p + 7;
                        skip = None;
                    } else {
                        break;
                    }
                    continue;
                }
            }
        }

        if bytes[i] == b'<' {
            if bytes[i..].starts_with(b"<!--") {
                i += 4;
                skip = Some(HtmlSkip::Comment);
                continue;
            }
            let Some(gt_off) = memchr(b'>', &bytes[i..]) else {
                break;
            };
            let tag_slice = &html[i + 1..i + gt_off];
            let trimmed = tag_slice.trim_start();
            let is_close = trimmed.starts_with('/');
            let name = trimmed
                .trim_start_matches('/')
                .split_whitespace()
                .next()
                .unwrap_or("");
            if !is_close && name.eq_ignore_ascii_case("script") {
                i += gt_off + 1;
                skip = Some(HtmlSkip::Script);
                continue;
            }
            if !is_close && name.eq_ignore_ascii_case("style") {
                i += gt_off + 1;
                skip = Some(HtmlSkip::Style);
                continue;
            }
            if !is_close && name.eq_ignore_ascii_case("head") {
                i += gt_off + 1;
                skip = Some(HtmlSkip::Head);
                continue;
            }
            if !is_close && name.eq_ignore_ascii_case("a") {
                if let Some(href) = extract_attr(tag_slice, "href") {
                    let content_start = i + gt_off + 1;
                    if let Some(end_off) = find_ci(&bytes[content_start..], b"</a>") {
                        let inner = &html[content_start..content_start + end_off];
                        let text = anchor_visible_text(inner);
                        out.push(Link {
                            text,
                            href: href.clone(),
                        });
                        i = content_start + end_off + 4;
                        continue;
                    }
                }
            }
            i += gt_off + 1;
            continue;
        }
        i += 1;
    }
}

/// Return decoded attachment `index` in the same order as [`parse_message`].attachments.
pub fn attachment(raw: &[u8], index: usize) -> Option<AttachmentData> {
    let (_, _, attachments) = walk_parts(raw, 0);
    attachments.get(index).map(|a| AttachmentData {
        filename: a.filename.clone(),
        content_type: a.content_type.clone(),
        bytes: a.bytes.clone(),
    })
}

fn extension_text_name(filename: &str) -> bool {
    let lower = filename.to_ascii_lowercase();
    lower.ends_with(".txt")
        || lower.ends_with(".csv")
        || lower.ends_with(".md")
        || lower.ends_with(".log")
}

fn is_text_content_type(ct: &str) -> bool {
    let ct = ct.to_ascii_lowercase();
    let main = ct.split(';').next().unwrap_or(&ct).trim();
    main.starts_with("text/")
        || main == "application/json"
        || main == "application/xml"
        || main == "text/csv"
        || main == "application/csv"
}

fn truncate_text(s: String, max_chars: usize) -> String {
    if s.chars().count() <= max_chars {
        return s;
    }
    s.chars().take(max_chars).collect()
}

/// Best-effort text extraction from a decoded attachment.
pub fn attachment_text(a: &AttachmentData, max_chars: usize) -> Result<String, String> {
    let ct = a.content_type.to_ascii_lowercase();
    let main = ct.split(';').next().unwrap_or(&ct).trim();

    if main == "application/pdf" {
        let text = extract_pdf_text(&a.bytes)?;
        return Ok(truncate_text(text, max_chars));
    }

    if is_text_content_type(&a.content_type) || extension_text_name(&a.filename) {
        let charset = get_param(&a.content_type, "charset").unwrap_or("utf-8");
        let decoded = decode_bytes_lossy(&a.bytes, charset);
        let text = if main.starts_with("text/html") || main == "application/xhtml+xml" {
            html_to_text_limited(&decoded, max_chars)
        } else {
            truncate_text(decoded, max_chars)
        };
        return Ok(text);
    }

    Err(format!(
        "binary attachment ({main}), text not available"
    ))
}

fn pdf_stream_markers(data: &[u8]) -> Vec<usize> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 6 < data.len() {
        if data[i..].starts_with(b"stream") {
            let after = i + 6;
            if after < data.len() && (data[after] == b'\r' || data[after] == b'\n') {
                let content_start = if data[after] == b'\r' && data.get(after + 1) == Some(&b'\n') {
                    after + 2
                } else {
                    after + 1
                };
                out.push(content_start);
            }
        }
        i += 1;
        if out.len() >= MAX_PDF_STREAMS {
            break;
        }
    }
    out
}

fn pdf_stream_end(data: &[u8], start: usize) -> Option<usize> {
    let hay = data.get(start..)?;
    hay.windows(9)
        .position(|w| w == b"endstream")
        .map(|p| start + p)
}

fn region_flate_decode(data: &[u8], stream_start: usize) -> bool {
    let lookback = stream_start.saturating_sub(512);
    let prefix = data.get(lookback..stream_start).unwrap_or(&[]);
    find_ci(prefix, b"FlateDecode").is_some()
}

fn extract_pdf_text(pdf: &[u8]) -> Result<String, String> {
    let mut inflated_total = 0usize;
    let mut text = String::new();
    for (streams, start) in pdf_stream_markers(pdf).into_iter().enumerate() {
        if streams >= MAX_PDF_STREAMS {
            break;
        }
        let Some(end) = pdf_stream_end(pdf, start) else {
            continue;
        };
        if !region_flate_decode(pdf, start) {
            let slice = pdf.get(start..end).unwrap_or(&[]);
            append_pdf_content_text(slice, &mut text);
            continue;
        }
        let slice = pdf.get(start..end).unwrap_or(&[]);
        let cap = MAX_PDF_INFLATED.saturating_sub(inflated_total).max(1);
        match zlib_inflate(slice, cap) {
            Ok(buf) => {
                inflated_total = inflated_total.saturating_add(buf.len());
                append_pdf_content_text(&buf, &mut text);
            }
            Err(_) => {
                append_pdf_content_text(slice, &mut text);
            }
        }
        if inflated_total >= MAX_PDF_INFLATED {
            break;
        }
    }
    if text.is_empty() {
        append_pdf_content_text(pdf, &mut text);
    }
    Ok(collapse_blank_lines(&text))
}

fn append_pdf_content_text(stream: &[u8], out: &mut String) {
    let s = if let Ok(t) = std::str::from_utf8(stream) {
        t
    } else {
        return;
    };
    let bytes = s.as_bytes();
    let mut i = 0usize;
    let mut in_string = false;
    while i < bytes.len() && out.len() < 2_000_000 {
        let b = bytes[i];
        if in_string {
            if b == b'\\' {
                if let Some(next) = bytes.get(i + 1) {
                    let ch = match next {
                        b'n' => '\n',
                        b'r' => '\r',
                        b't' => '\t',
                        b'b' => '\x08',
                        b'f' => '\x0c',
                        b'(' | b')' | b'\\' => *next as char,
                        d if d.is_ascii_digit() => {
                            let mut oct = String::new();
                            oct.push(*next as char);
                            for k in 2..4 {
                                if let Some(d2) = bytes.get(i + k).filter(|c| c.is_ascii_digit()) {
                                    oct.push(*d2 as char);
                                }
                            }
                            let code = u32::from_str_radix(&oct, 8).unwrap_or(0);
                            i += oct.len().saturating_sub(1);
                            char::from_u32(code).unwrap_or(' ')
                        }
                        _ => *next as char,
                    };
                    out.push(ch);
                    i += 2;
                    continue;
                }
            } else if b == b')' {
                in_string = false;
                i += 1;
                continue;
            } else if b == b'(' {
                i += 1;
                continue;
            } else if b.is_ascii() && b >= 0x20 && b != b'%' {
                out.push(b as char);
            }
            i += 1;
            continue;
        }
        if b == b'(' {
            in_string = true;
            i += 1;
            continue;
        }
        if b == b'<' {
            if let Some((hex, next)) = read_pdf_hex_string(bytes, i + 1) {
                out.push_str(&hex);
                i = next;
                continue;
            }
        }
        if bytes[i..].starts_with(b"ET") {
            out.push('\n');
            i += 2;
            continue;
        }
        if bytes[i..].starts_with(b"T*") {
            out.push('\n');
            i += 2;
            continue;
        }
        if bytes[i..].starts_with(b"Td") || bytes[i..].starts_with(b"TD") {
            out.push('\n');
            i += 2;
            continue;
        }
        i += 1;
    }
}

fn read_pdf_hex_string(bytes: &[u8], start: usize) -> Option<(String, usize)> {
    let mut out = String::new();
    let mut i = start;
    let mut nibbles = 0u8;
    let mut val = 0u8;
    while i < bytes.len() && bytes[i] != b'>' {
        let b = bytes[i];
        if b.is_ascii_whitespace() {
            i += 1;
            continue;
        }
        let n = hex_nibble(b)?;
        if nibbles == 0 {
            val = n << 4;
            nibbles = 1;
        } else {
            val |= n;
            nibbles = 0;
            if val >= 0x20 && val != 0x7f {
                out.push(val as char);
            }
        }
        i += 1;
        if out.len() > 500_000 {
            break;
        }
    }
    if bytes.get(i) == Some(&b'>') {
        i += 1;
    }
    Some((out, i))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc2047_whitespace_and_q_words() {
        let d = decode_header_value;
        assert_eq!(d("=?utf-8?B?QWxpY2U=?= <a@x.com>"), "Alice <a@x.com>");
        assert_eq!(d("Re: =?utf-8?Q?caf=C3=A9?= time"), "Re: café time");
        assert_eq!(d("=?utf-8?Q?=C3=A9t=C3=A9?="), "été");
        assert_eq!(d("=?utf-8?Q?a?= =?utf-8?Q?b?="), "ab");
        assert_eq!(d("=?utf-8?Q?a?=\r\n =?utf-8?Q?_b?="), "a b");
        assert_eq!(d("\"=?utf-8?B?Qm9i?=\" <b@y.com>"), "\"Bob\" <b@y.com>");
        assert_eq!(d("=?windows-1252?Q?=93hi=94?="), "\u{201c}hi\u{201d}");
        assert_eq!(d("=?bogus =? not a word"), "=?bogus =? not a word");
        assert_eq!(d("=?utf-8?X?abc?="), "=?utf-8?X?abc?=");
    }

    #[test]
    fn rfc2047_utf8() {
        let raw = b"Subject: =?UTF-8?B?SGVsbG8gV29ybGQ=?=\r\n\r\n";
        let h = parse_headers(raw);
        assert!(h.subject.contains("Hello"));
    }

    #[test]
    fn qp_and_b64() {
        let qp = qp_decode(b"hello=3Dworld");
        assert_eq!(qp, b"hello=world");
        let b = b64_decode(b"SGVsbG8=");
        assert_eq!(b, b"Hello");
    }

    #[test]
    fn multipart_alternative() {
        let raw = concat!(
            "From: a@b.com\r\n",
            "Content-Type: multipart/alternative; boundary=abc\r\n\r\n",
            "--abc\r\n",
            "Content-Type: text/html; charset=utf-8\r\n\r\n",
            "<p>Hi</p>\r\n",
            "--abc\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n\r\n",
            "Hi plain\r\n",
            "--abc--\r\n",
        );
        let m = parse_message(raw.as_bytes(), 10_000);
        assert_eq!(m.body.trim(), "Hi plain");
        assert!(!m.body_from_html);
    }

    #[test]
    fn html_only() {
        let raw = "Content-Type: text/html\r\n\r\n<p>Line</p><br>";
        let m = parse_message(raw.as_bytes(), 10_000);
        assert!(m.body_from_html);
        assert!(m.body.contains("Line"));
    }

    #[test]
    fn attachment_index_and_text() {
        let raw = concat!(
            "Content-Type: multipart/mixed; boundary=b\r\n\r\n",
            "--b\r\n",
            "Content-Type: text/plain\r\n\r\n",
            "body\r\n",
            "--b\r\n",
            "Content-Disposition: attachment; filename=\"f.txt\"\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "Content-Transfer-Encoding: base64\r\n\r\n",
            "ZGF0YQ==\r\n",
            "--b--\r\n",
        );
        let att = attachment(raw.as_bytes(), 0).expect("att");
        assert_eq!(att.bytes, b"data");
        let text = attachment_text(&att, 1000).expect("text");
        assert_eq!(text, "data");
        let m = parse_message(raw.as_bytes(), 10_000);
        assert_eq!(m.attachments.len(), 1);
        assert_eq!(m.attachments[0].size, 4);
    }

    #[test]
    fn attachment_disposition() {
        let raw = concat!(
            "Content-Type: multipart/mixed; boundary=b\r\n\r\n",
            "--b\r\n",
            "Content-Type: text/plain\r\n\r\n",
            "body\r\n",
            "--b\r\n",
            "Content-Disposition: attachment; filename=\"f.txt\"\r\n",
            "Content-Type: application/octet-stream\r\n",
            "Content-Transfer-Encoding: base64\r\n\r\n",
            "ZGF0YQ==\r\n",
            "--b--\r\n",
        );
        let m = parse_message(raw.as_bytes(), 10_000);
        assert_eq!(m.attachments.len(), 1);
        assert_eq!(m.attachments[0].size, 4);
        assert!(m.attachments[0].filename.contains("f.txt"));
    }

    #[test]
    fn malformed_truncated() {
        let _ = parse_message(b"From: x\r\n", 100);
        let _ = parse_headers(b"Incomplete: =?UTF-8?B?");
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
    fn fuzz_headers_and_message() {
        let mut rng = XorShift::new(99);
        for _ in 0..3000 {
            let len = (rng.next() as usize % 400) + 50;
            let mut buf = vec![0u8; len];
            for b in &mut buf {
                *b = rng.next();
            }
            let _ = parse_headers(&buf);
            let _ = parse_message(&buf, 500);
            let t = rng.next() as usize % buf.len().max(1);
            if !buf.is_empty() {
                let _ = parse_message(&buf[..t.min(buf.len())], 500);
            }
        }
    }

    #[test]
    fn entity_after_non_ascii_does_not_panic() {
        let raw = "Content-Type: text/html; charset=utf-8\r\n\r\n<p>Caf\u{e9} &amp; more</p>";
        let m = parse_message(raw.as_bytes(), 10_000);
        assert!(m.body.contains("Caf\u{e9}"));
        assert!(m.body.contains('&') || m.body.contains(' '));
    }

    #[test]
    fn utf8_html_body_not_mojibake() {
        let raw = "Content-Type: text/html; charset=utf-8\r\n\r\n<p>Caf\u{e9}</p>";
        let m = parse_message(raw.as_bytes(), 10_000);
        assert_eq!(m.body, "Caf\u{e9}");
    }

    #[test]
    fn multipart_8bit_utf8_body() {
        let raw = concat!(
            "Content-Type: multipart/mixed; boundary=b\r\n\r\n",
            "--b\r\n",
            "Content-Type: text/plain; charset=utf-8\r\n",
            "Content-Transfer-Encoding: 8bit\r\n\r\n",
            "Caf\u{e9}\r\n",
            "--b--\r\n",
        );
        let m = parse_message(raw.as_bytes(), 10_000);
        assert_eq!(m.body, "Caf\u{e9}");
    }

    #[test]
    fn raw_utf8_subject_header() {
        let h = parse_headers("Subject: Caf\u{e9}\r\n\r\n".as_bytes());
        assert_eq!(h.subject, "Caf\u{e9}");
    }

    #[test]
    fn newsletter_curly_apostrophe_and_nbsp() {
        let html = "<p>We\u{2019}re here&nbsp;for you</p>";
        let b64 = {
            const T: &[u8] =
                b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
            let b = html.as_bytes();
            let mut o = String::new();
            for c in b.chunks(3) {
                let n = (u32::from(c[0]) << 16)
                    | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
                    | u32::from(*c.get(2).unwrap_or(&0));
                for k in 0..4 {
                    if k <= c.len() {
                        o.push(T[((n >> (18 - 6 * k)) & 63) as usize] as char);
                    } else {
                        o.push('=');
                    }
                }
            }
            o
        };
        let raw = format!(
            "Content-Type: multipart/alternative; boundary=b\r\n\r\n--b\r\n\
             Content-Type: text/html; charset=utf-8\r\nContent-Transfer-Encoding: base64\r\n\r\n\
             {b64}\r\n--b--\r\n"
        );
        let m = parse_message(raw.as_bytes(), 10_000);
        assert!(m.body.contains("We\u{2019}re"));
        assert!(m.body.contains("for you"));
    }

    #[test]
    fn multipart_mixed_html_only_sets_body_from_html() {
        let raw = concat!(
            "Content-Type: multipart/mixed; boundary=b\r\n\r\n",
            "--b\r\n",
            "Content-Type: text/html; charset=utf-8\r\n\r\n",
            "<p>Hi</p>\r\n",
            "--b--\r\n",
        );
        let m = parse_message(raw.as_bytes(), 10_000);
        assert!(m.body_from_html);
        assert!(m.body.contains("Hi"));
    }

    #[test]
    fn header_section_splits() {
        let raw = b"From: a@b.com\r\nTo: c@d.com\r\n\r\nbody";
        assert_eq!(header_section(raw), b"From: a@b.com\r\nTo: c@d.com");
        let raw2 = b"H: v\n\nbody";
        assert_eq!(header_section(raw2), b"H: v");
    }

    #[test]
    fn html_links_href_and_text() {
        let raw = concat!(
            "Content-Type: text/html; charset=utf-8\r\n\r\n",
            "<p>Go to <a href=\"https://evil.ru/x\">www.paypal.com</a> now</p>",
        );
        let links = html_links(raw.as_bytes(), 10);
        assert_eq!(links.len(), 1);
        assert!(links[0].text.contains("paypal"));
        assert!(links[0].href.contains("evil.ru"));
    }

    #[test]
    fn html_links_respects_max() {
        let raw = "Content-Type: text/html\r\n\r\n\
                   <a href=a>1</a><a href=b>2</a><a href=c>3</a>";
        assert_eq!(html_links(raw.as_bytes(), 2).len(), 2);
    }

    #[test]
    fn pathological_html_converts_quickly() {
        use std::time::Instant;
        let body = format!(
            "{}{}{}",
            "&amp;".repeat(400_000),
            "<a href=x>".repeat(100_000),
            "<!--".repeat(100_000),
        );
        let raw = format!("Content-Type: text/html\r\n\r\n{body}");
        let t = Instant::now();
        let _ = parse_message(raw.as_bytes(), 1000);
        assert!(
            t.elapsed().as_secs_f64() < 2.0,
            "took {:.2}s",
            t.elapsed().as_secs_f64()
        );
    }
}