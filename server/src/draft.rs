//! RFC 5322 draft builder. See docs/WRITE-CONTRACT.md.

const MAX_LINE: usize = 76;

fn reject_header_injection(s: &str) -> Result<(), String> {
    if s.bytes().any(|b| b == b'\r' || b == b'\n' || b == 0) {
        return Err("header value contains CR, LF, or NUL".into());
    }
    Ok(())
}

fn validate_address(addr: &str) -> Result<(), String> {
    reject_header_injection(addr)?;
    let addr = addr.trim();
    let Some((local, domain)) = addr.rsplit_once('@') else {
        return Err(format!("{addr:?} is not an address of the form name@example.com"));
    };
    // RFC 5322 dot-atom: no quoted local parts, no display names, no angle brackets.
    let atext = |c: char| c.is_ascii_alphanumeric() || "!#$%&'*+/=?^_`{|}~-".contains(c);
    let dot_atom = |s: &str, ok: &dyn Fn(char) -> bool| {
        !s.is_empty() && s.split('.').all(|seg| !seg.is_empty() && seg.chars().all(ok))
    };
    let domain_ok = dot_atom(domain, &|c: char| c.is_ascii_alphanumeric() || c == '-') && domain.contains('.');
    if !dot_atom(local, &atext) || !domain_ok || addr.len() > 254 {
        return Err(format!("{addr:?} is not an address of the form name@example.com"));
    }
    Ok(())
}

fn validate_addresses(list: &[String]) -> Result<(), String> {
    for a in list {
        validate_address(a)?;
    }
    Ok(())
}

fn is_ascii_only(s: &str) -> bool {
    s.is_ascii()
}

fn b64_encode(data: &[u8]) -> String {
    const T: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let n = (u32::from(chunk[0]) << 16)
            | (u32::from(*chunk.get(1).unwrap_or(&0)) << 8)
            | u32::from(*chunk.get(2).unwrap_or(&0));
        for k in 0..4 {
            if k <= chunk.len() {
                out.push(T[((n >> (18 - 6 * k)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// RFC 2047 encoded words, each at most 75 characters, split on character boundaries and joined
/// by folding whitespace (which decoders drop between adjacent encoded words).
fn encode_rfc2047_b_utf8(subject: &str) -> String {
    // "=?utf-8?B?" + "?=" is 12 characters; 60 base64 characters carry 45 bytes.
    const MAX_CHUNK: usize = 45;
    let mut words = Vec::new();
    let mut chunk = String::new();
    for c in subject.chars() {
        if chunk.len() + c.len_utf8() > MAX_CHUNK {
            words.push(format!("=?utf-8?B?{}?=", b64_encode(chunk.as_bytes())));
            chunk.clear();
        }
        chunk.push(c);
    }
    if !chunk.is_empty() {
        words.push(format!("=?utf-8?B?{}?=", b64_encode(chunk.as_bytes())));
    }
    words.join("\r\n ")
}

/// Fold at whitespace only, so unfolding gives back the exact value. A single word longer than
/// the line stays on its own line (RFC 5322 allows up to 998 characters).
fn fold_header_line(name: &str, value: &str) -> String {
    let mut out = format!("{name}:");
    let mut line_len = out.len();
    for (i, segment) in value.split("\r\n ").enumerate() {
        // Pre-folded encoded words arrive joined by CRLF SP: keep those breaks.
        if i > 0 {
            out.push_str("\r\n");
            line_len = 0;
        }
        for word in segment.split(' ') {
            if line_len > 0 && line_len + 1 + word.len() > MAX_LINE {
                out.push_str("\r\n");
                line_len = 0;
            }
            out.push(' ');
            out.push_str(word);
            line_len += 1 + word.len();
        }
    }
    out.push_str("\r\n");
    out
}

/// Quoted-printable (RFC 2045): line breaks in the text stay hard CRLF breaks, soft breaks keep
/// lines at 76 characters, and a space or tab before a break is encoded.
fn qp_encode_body(body: &str) -> String {
    let normalized = body.replace("\r\n", "\n").replace('\r', "\n");
    let mut out = String::new();
    for (n, line) in normalized.split('\n').enumerate() {
        if n > 0 {
            out.push_str("\r\n");
        }
        let bytes = line.as_bytes();
        let mut line_len = 0usize;
        for (i, &b) in bytes.iter().enumerate() {
            let last = i + 1 == bytes.len();
            let plain = (0x21..=0x7E).contains(&b) && b != b'=' || (b == b' ' && !last);
            let token = if plain { (b as char).to_string() } else { format!("={b:02X}") };
            // Leave room for the "=" of a soft break.
            if line_len + token.len() > MAX_LINE - 1 {
                out.push_str("=\r\n");
                line_len = 0;
            }
            out.push_str(&token);
            line_len += token.len();
        }
    }
    out
}

fn format_address_list(addrs: &[String]) -> String {
    addrs.join(", ")
}

/// Build a MIME message for APPEND to Drafts.
#[allow(clippy::too_many_arguments)]
pub fn build_draft(
    from: &str,
    to: &[String],
    cc: &[String],
    subject: &str,
    body: &str,
    in_reply_to: Option<&str>,
    references: Option<&str>,
    date: &str,
    message_id: &str,
) -> Result<Vec<u8>, String> {
    reject_header_injection(from)?;
    reject_header_injection(subject)?;
    reject_header_injection(date)?;
    reject_header_injection(message_id)?;
    validate_address(from)?;
    validate_addresses(to)?;
    validate_addresses(cc)?;
    if to.is_empty() {
        return Err("To is required".into());
    }
    if let Some(v) = in_reply_to {
        reject_header_injection(v)?;
    }
    if let Some(v) = references {
        reject_header_injection(v)?;
    }

    let subject_val = if is_ascii_only(subject) {
        subject.to_string()
    } else {
        encode_rfc2047_b_utf8(subject)
    };

    let mut msg = String::new();
    msg.push_str(&fold_header_line("From", from));
    msg.push_str(&fold_header_line("To", &format_address_list(to)));
    if !cc.is_empty() {
        msg.push_str(&fold_header_line("Cc", &format_address_list(cc)));
    }
    msg.push_str(&fold_header_line("Subject", &subject_val));
    msg.push_str(&fold_header_line("Date", date));
    msg.push_str(&fold_header_line("Message-ID", message_id));
    if let Some(irt) = in_reply_to {
        msg.push_str(&fold_header_line("In-Reply-To", irt));
    }
    if let Some(refs) = references {
        msg.push_str(&fold_header_line("References", refs));
    }
    msg.push_str("MIME-Version: 1.0\r\n");
    msg.push_str("Content-Type: text/plain; charset=utf-8\r\n");
    msg.push_str("Content-Transfer-Encoding: quoted-printable\r\n");
    msg.push_str("\r\n");
    msg.push_str(&qp_encode_body(body));
    msg.push_str("\r\n");
    Ok(msg.into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_args() -> (&'static str, Vec<String>, Vec<String>, &'static str, &'static str) {
        (
            "sender@example.com",
            vec!["to@example.com".into()],
            vec![],
            "Hello",
            "Body line",
        )
    }

    #[test]
    fn builds_basic_draft() {
        let (from, to, cc, subject, body) = base_args();
        let out = build_draft(
            from,
            &to,
            &cc,
            subject,
            body,
            None,
            None,
            "Mon, 1 Jan 2024 12:00:00 +0000",
            "<msg-1@example.com>",
        )
        .expect("draft");
        let s = String::from_utf8(out).expect("utf8");
        assert!(s.starts_with("From: sender@example.com\r\n"));
        assert!(s.contains("Content-Transfer-Encoding: quoted-printable\r\n"));
        assert!(s.contains("Body line"));
    }

    #[test]
    fn rejects_crlf_injection() {
        let (from, to, cc, _, body) = base_args();
        let err = build_draft(
            from,
            &to,
            &cc,
            "evil\r\nBcc: spy@evil.com",
            body,
            None,
            None,
            "Mon, 1 Jan 2024 12:00:00 +0000",
            "<x@y.com>",
        )
        .unwrap_err();
        assert!(err.contains("CR"));
    }

    #[test]
    fn rejects_bad_address() {
        let (from, _, cc, subject, body) = base_args();
        let err = build_draft(
            from,
            &["not-an-email".into()],
            &cc,
            subject,
            body,
            None,
            None,
            "Mon, 1 Jan 2024 12:00:00 +0000",
            "<x@y.com>",
        )
        .unwrap_err();
        assert!(!err.is_empty());
    }

    #[test]
    fn non_ascii_subject_encoded() {
        let (from, to, cc, _, body) = base_args();
        let out = build_draft(
            from,
            &to,
            &cc,
            "café",
            body,
            None,
            None,
            "Mon, 1 Jan 2024 12:00:00 +0000",
            "<x@y.com>",
        )
        .expect("draft");
        let s = String::from_utf8(out).unwrap();
        assert!(s.contains("=?utf-8?B?"));
    }

    fn round_trip(subject: &str, body: &str) -> crate::mime::Message {
        let raw = build_draft(
            "me@example.com",
            &["a+tag@example.co.uk".into()],
            &[],
            subject,
            body,
            None,
            None,
            "Mon, 1 Jan 2024 12:00:00 +0000",
            "<x@example.com>",
        )
        .expect("draft");
        let text = String::from_utf8(raw.clone()).expect("utf8");
        for line in text.split("\r\n") {
            assert!(line.len() <= 998, "line too long");
            assert!(!line.contains('\n') && !line.contains('\r'), "bare CR or LF");
        }
        crate::mime::parse_message(&raw, 100_000)
    }

    #[test]
    fn long_subjects_and_bodies_survive_a_round_trip() {
        let ascii = "Quarterly invoice reminder for the property at 123 Long Street, please review before Friday";
        assert_eq!(round_trip(ascii, "x").headers.subject, ascii);
        let utf8 = "Résumé et café — réunion très importante à propos du budget 2026 ✅ ünïcödé";
        assert_eq!(round_trip(utf8, "x").headers.subject, utf8);
        let body = "Hi there,\n\nLine two has = signs and trailing space \nCafé ☕\r\n".to_string() + &"long ".repeat(40);
        let m = round_trip("s", &body);
        let want = body.replace("\r\n", "\n");
        assert_eq!(m.body.trim_end(), want.trim_end());
    }

    #[test]
    fn addresses() {
        for ok in ["a+tag@example.com", "first.last@sub.example.org", "o'brien@example.ie"] {
            assert!(validate_address(ok).is_ok(), "{ok}");
        }
        for bad in ["x", "a@b", "a@@b.com", "Name <a@b.com>", "a@b.com,c@d.com", ".a@b.com", "a..b@c.com", "a@-.com x"] {
            assert!(validate_address(bad).is_err(), "{bad}");
        }
    }
}
