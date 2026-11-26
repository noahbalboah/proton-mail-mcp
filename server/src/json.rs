//! Strict RFC 8259 JSON parser and serializer.

const MAX_INPUT: usize = 1 << 20; // 1 MiB
const MAX_DEPTH: usize = 64;
const MAX_STRING: usize = 1 << 20; // 1 MiB
const MAX_ELEMENTS: usize = 10_000;

#[derive(Debug, Clone, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Array(Vec<Json>),
    Object(Vec<(String, Json)>),
}

impl Json {
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Object(pairs) => pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::String(s) => Some(s.as_str()),
            _ => None,
        }
    }

    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Json::Bool(b) => Some(*b),
            _ => None,
        }
    }

    pub fn as_u64(&self) -> Option<u64> {
        let Json::Number(s) = self else {
            return None;
        };
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        s.parse::<u64>().ok()
    }

    pub fn as_object(&self) -> Option<&[(String, Json)]> {
        match self {
            Json::Object(pairs) => Some(pairs.as_slice()),
            _ => None,
        }
    }

    pub fn str(s: impl Into<String>) -> Json {
        Json::String(s.into())
    }

    pub fn obj<const N: usize>(pairs: [(&str, Json); N]) -> Json {
        Json::Object(pairs.into_iter().map(|(k, v)| (k.to_string(), v)).collect())
    }
}

impl std::fmt::Display for Json {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Json::Null => f.write_str("null"),
            Json::Bool(true) => f.write_str("true"),
            Json::Bool(false) => f.write_str("false"),
            Json::Number(n) => f.write_str(n),
            Json::String(s) => {
                f.write_str("\"")?;
                for ch in s.chars() {
                    match ch {
                        '"' => f.write_str("\\\"")?,
                        '\\' => f.write_str("\\\\")?,
                        c if (c as u32) < 0x20 => {
                            write!(f, "\\u{:04x}", c as u32)?;
                        }
                        c => {
                            let mut buf = [0u8; 4];
                            let encoded = c.encode_utf8(&mut buf);
                            f.write_str(encoded)?;
                        }
                    }
                }
                f.write_str("\"")
            }
            Json::Array(arr) => {
                f.write_str("[")?;
                for (i, item) in arr.iter().enumerate() {
                    if i > 0 {
                        f.write_str(",")?;
                    }
                    write!(f, "{item}")?;
                }
                f.write_str("]")
            }
            Json::Object(pairs) => {
                f.write_str("{")?;
                for (i, (k, v)) in pairs.iter().enumerate() {
                    if i > 0 {
                        f.write_str(",")?;
                    }
                    write!(f, "{}", Json::String(k.clone()))?;
                    f.write_str(":")?;
                    write!(f, "{v}")?;
                }
                f.write_str("}")
            }
        }
    }
}

struct Parser<'a> {
    input: &'a [u8],
    pos: usize,
    depth: usize,
}

impl<'a> Parser<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self {
            input,
            pos: 0,
            depth: 0,
        }
    }

    fn err(&self, msg: &str) -> String {
        msg.to_string()
    }

    fn peek(&self) -> Option<u8> {
        self.input.get(self.pos).copied()
    }

    fn bump(&mut self) -> Option<u8> {
        let b = self.peek()?;
        self.pos = self.pos.saturating_add(1);
        Some(b)
    }

    fn skip_ws(&mut self) {
        while let Some(b) = self.peek() {
            if matches!(b, b' ' | b'\t' | b'\n' | b'\r') {
                self.bump();
            } else {
                break;
            }
        }
    }

    fn parse_value(&mut self) -> Result<Json, String> {
        if self.depth > MAX_DEPTH {
            return Err(self.err("max depth"));
        }
        self.skip_ws();
        let b = self.peek().ok_or_else(|| self.err("unexpected end"))?;
        match b {
            b'n' => self.parse_null(),
            b't' | b'f' => self.parse_bool(),
            b'"' => self.parse_string().map(Json::String),
            b'-' | b'0'..=b'9' => self.parse_number().map(Json::Number),
            b'[' => self.parse_array(),
            b'{' => self.parse_object(),
            _ => Err(self.err("invalid value")),
        }
    }

    fn parse_null(&mut self) -> Result<Json, String> {
        let lit = b"null";
        for &c in lit {
            if self.bump() != Some(c) {
                return Err(self.err("invalid null"));
            }
        }
        Ok(Json::Null)
    }

    fn parse_bool(&mut self) -> Result<Json, String> {
        if self.peek() == Some(b't') {
            for &c in b"true" {
                if self.bump() != Some(c) {
                    return Err(self.err("invalid true"));
                }
            }
            Ok(Json::Bool(true))
        } else {
            for &c in b"false" {
                if self.bump() != Some(c) {
                    return Err(self.err("invalid false"));
                }
            }
            Ok(Json::Bool(false))
        }
    }

    fn parse_string(&mut self) -> Result<String, String> {
        if self.bump() != Some(b'"') {
            return Err(self.err("expected quote"));
        }
        let mut out = String::new();
        let mut raw_chars = 0usize;
        loop {
            let b = self.bump().ok_or_else(|| self.err("unterminated string"))?;
            if b == b'"' {
                break;
            }
            if b == b'\\' {
                let esc = self.bump().ok_or_else(|| self.err("bad escape"))?;
                match esc {
                    b'"' => out.push('"'),
                    b'\\' => out.push('\\'),
                    b'/' => out.push('/'),
                    b'b' => out.push('\x08'),
                    b'f' => out.push('\x0c'),
                    b'n' => out.push('\n'),
                    b'r' => out.push('\r'),
                    b't' => out.push('\t'),
                    b'u' => {
                        let hi = self.parse_u16_hex()?;
                        let ch = if (0xD800..=0xDBFF).contains(&hi) {
                            if self.bump() != Some(b'\\') || self.bump() != Some(b'u') {
                                return Err(self.err("lone high surrogate"));
                            }
                            let lo = self.parse_u16_hex()?;
                            if !(0xDC00..=0xDFFF).contains(&lo) {
                                return Err(self.err("invalid surrogate pair"));
                            }
                            char::from_u32(
                                0x10000
                                    + ((u32::from(hi - 0xD800) << 10) | u32::from(lo - 0xDC00)),
                            )
                            .ok_or_else(|| self.err("invalid code point"))?
                        } else if (0xDC00..=0xDFFF).contains(&hi) {
                            return Err(self.err("lone low surrogate"));
                        } else {
                            char::from_u32(u32::from(hi))
                                .ok_or_else(|| self.err("invalid code point"))?
                        };
                        out.push(ch);
                    }
                    _ => return Err(self.err("invalid escape")),
                }
            } else if b < 0x20 {
                return Err(self.err("control in string"));
            } else {
                let slice_start = self.pos - 1;
                let rest = self.input.get(slice_start..).ok_or_else(|| self.err("eof"))?;
                let ch_len = match rest.first() {
                    Some(x) if *x < 0x80 => 1,
                    Some(x) if *x & 0xE0 == 0xC0 => {
                        if rest.len() < 2 {
                            return Err(self.err("invalid utf-8"));
                        }
                        2
                    }
                    Some(x) if *x & 0xF0 == 0xE0 => {
                        if rest.len() < 3 {
                            return Err(self.err("invalid utf-8"));
                        }
                        3
                    }
                    Some(x) if *x & 0xF8 == 0xF0 => {
                        if rest.len() < 4 {
                            return Err(self.err("invalid utf-8"));
                        }
                        4
                    }
                    _ => return Err(self.err("invalid utf-8")),
                };
                let chunk = rest.get(..ch_len).ok_or_else(|| self.err("utf-8"))?;
                let s = std::str::from_utf8(chunk).map_err(|_| self.err("invalid utf-8"))?;
                if let Some(c) = s.chars().next() {
                    out.push(c);
                    for _ in 1..ch_len {
                        self.bump();
                    }
                }
            }
            raw_chars = raw_chars.saturating_add(1);
            if out.len() > MAX_STRING || raw_chars > MAX_STRING {
                return Err(self.err("string too long"));
            }
        }
        Ok(out)
    }

    fn parse_u16_hex(&mut self) -> Result<u16, String> {
        let mut n: u32 = 0;
        for _ in 0..4 {
            let b = self.bump().ok_or_else(|| self.err("hex"))?;
            let digit = match b {
                b'0'..=b'9' => u32::from(b - b'0'),
                b'a'..=b'f' => u32::from(b - b'a' + 10),
                b'A'..=b'F' => u32::from(b - b'A' + 10),
                _ => return Err(self.err("hex")),
            };
            n = n
                .checked_mul(16)
                .and_then(|x| x.checked_add(digit))
                .ok_or_else(|| self.err("hex overflow"))?;
        }
        u16::try_from(n).map_err(|_| self.err("hex"))
    }

    fn parse_number(&mut self) -> Result<String, String> {
        let start = self.pos;
        if self.peek() == Some(b'-') {
            self.bump();
        }
        match self.peek() {
            Some(b'0') => {
                self.bump();
                if self.peek().is_some_and(|b| b.is_ascii_digit()) {
                    return Err(self.err("leading zero"));
                }
            }
            Some(b'1'..=b'9') => {
                while self.peek().is_some_and(|b| b.is_ascii_digit()) {
                    self.bump();
                }
            }
            _ => return Err(self.err("invalid number")),
        }
        if self.peek() == Some(b'.') {
            self.bump();
            if !self.peek().is_some_and(|b| b.is_ascii_digit()) {
                return Err(self.err("invalid fraction"));
            }
            while self.peek().is_some_and(|b| b.is_ascii_digit()) {
                self.bump();
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.bump();
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.bump();
            }
            if !self.peek().is_some_and(|b| b.is_ascii_digit()) {
                return Err(self.err("invalid exponent"));
            }
            while self.peek().is_some_and(|b| b.is_ascii_digit()) {
                self.bump();
            }
        }
        let s = std::str::from_utf8(&self.input[start..self.pos]).map_err(|_| self.err("utf8"))?;
        if s.eq_ignore_ascii_case("nan") || s.eq_ignore_ascii_case("infinity") || s == "inf" {
            return Err(self.err("nan/inf"));
        }
        Ok(s.to_string())
    }

    fn parse_array(&mut self) -> Result<Json, String> {
        if self.bump() != Some(b'[') {
            return Err(self.err("expected ["));
        }
        self.depth = self.depth.saturating_add(1);
        if self.depth > MAX_DEPTH {
            self.depth = self.depth.saturating_sub(1);
            return Err(self.err("max depth"));
        }
        self.skip_ws();
        let mut arr = Vec::new();
        if self.peek() == Some(b']') {
            self.bump();
            self.depth = self.depth.saturating_sub(1);
            return Ok(Json::Array(arr));
        }
        loop {
            if arr.len() >= MAX_ELEMENTS {
                self.depth = self.depth.saturating_sub(1);
                return Err(self.err("too many elements"));
            }
            arr.push(self.parse_value()?);
            self.skip_ws();
            match self.bump() {
                Some(b']') => break,
                Some(b',') => {
                    self.skip_ws();
                }
                _ => {
                    self.depth = self.depth.saturating_sub(1);
                    return Err(self.err("expected , or ]"));
                }
            }
        }
        self.depth = self.depth.saturating_sub(1);
        Ok(Json::Array(arr))
    }

    fn parse_object(&mut self) -> Result<Json, String> {
        if self.bump() != Some(b'{') {
            return Err(self.err("expected {"));
        }
        self.depth = self.depth.saturating_add(1);
        if self.depth > MAX_DEPTH {
            self.depth = self.depth.saturating_sub(1);
            return Err(self.err("max depth"));
        }
        self.skip_ws();
        let mut pairs = Vec::new();
        let mut keys = std::collections::HashSet::new();
        if self.peek() == Some(b'}') {
            self.bump();
            self.depth = self.depth.saturating_sub(1);
            return Ok(Json::Object(pairs));
        }
        loop {
            if pairs.len() >= MAX_ELEMENTS {
                self.depth = self.depth.saturating_sub(1);
                return Err(self.err("too many elements"));
            }
            self.skip_ws();
            let key = self.parse_string()?;
            if !keys.insert(key.clone()) {
                self.depth = self.depth.saturating_sub(1);
                return Err(self.err("duplicate key"));
            }
            self.skip_ws();
            if self.bump() != Some(b':') {
                self.depth = self.depth.saturating_sub(1);
                return Err(self.err("expected :"));
            }
            let val = self.parse_value()?;
            pairs.push((key, val));
            self.skip_ws();
            match self.bump() {
                Some(b'}') => break,
                Some(b',') => {}
                _ => {
                    self.depth = self.depth.saturating_sub(1);
                    return Err(self.err("expected , or }"));
                }
            }
        }
        self.depth = self.depth.saturating_sub(1);
        Ok(Json::Object(pairs))
    }

    fn finish(mut self) -> Result<Json, String> {
        let v = self.parse_value()?;
        self.skip_ws();
        if self.pos < self.input.len() {
            return Err(self.err("trailing content"));
        }
        Ok(v)
    }
}

pub fn parse(input: &[u8]) -> Result<Json, String> {
    if input.len() > MAX_INPUT {
        return Err("input too large".to_string());
    }
    if std::str::from_utf8(input).is_err() {
        return Err("invalid utf-8".to_string());
    }
    Parser::new(input).finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_bool() {
        assert_eq!(parse(b" null ").unwrap(), Json::Null);
        assert_eq!(parse(b"true").unwrap(), Json::Bool(true));
        assert_eq!(parse(b"false").unwrap(), Json::Bool(false));
    }

    #[test]
    fn numbers() {
        assert_eq!(parse(b"0").unwrap(), Json::Number("0".into()));
        assert_eq!(parse(b"-1").unwrap(), Json::Number("-1".into()));
        assert_eq!(parse(b"1.5e10").unwrap(), Json::Number("1.5e10".into()));
        assert!(parse(b"01").is_err());
        assert!(parse(b"NaN").is_err());
    }

    #[test]
    fn strings_and_escapes() {
        assert_eq!(
            parse(br#""hello""#).unwrap(),
            Json::String("hello".into())
        );
        assert_eq!(
            parse(br#""\u0041""#).unwrap(),
            Json::String("A".into())
        );
        let pair = r#""\uD800\uDC00""#;
        assert_eq!(
            parse(pair.as_bytes()).unwrap(),
            Json::String("\u{10000}".into())
        );
        assert!(parse(br#""\uD800""#).is_err());
        assert!(parse(br#""\uDC00""#).is_err());
    }

    #[test]
    fn array_object() {
        assert_eq!(
            parse(b"[1,2,3]").unwrap(),
            Json::Array(vec![
                Json::Number("1".into()),
                Json::Number("2".into()),
                Json::Number("3".into())
            ])
        );
        assert!(parse(b"[1,]").is_err());
        assert!(parse(br#"{"a":1,"a":2}"#).is_err());
    }

    #[test]
    fn duplicate_key() {
        assert!(parse(br#"{"x":1,"x":2}"#).is_err());
    }

    #[test]
    fn trailing() {
        assert!(parse(b"{}x").is_err());
    }

    #[test]
    fn limits() {
        assert!(parse(&vec![b'a'; MAX_INPUT + 1]).is_err());
    }

    #[test]
    fn accessors() {
        let j = Json::obj([("k", Json::str("v"))]);
        assert_eq!(j.get("k").and_then(|x| x.as_str()), Some("v"));
        assert_eq!(Json::Number("42".into()).as_u64(), Some(42));
        assert_eq!(Json::Number("-1".into()).as_u64(), None);
    }

    #[test]
    fn display_roundtrip() {
        let j = Json::obj([
            ("a", Json::Null),
            ("b", Json::str("hi\n")),
        ]);
        let s = j.to_string();
        assert_eq!(parse(s.as_bytes()).unwrap(), j);
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
    fn fuzz_no_panic() {
        let mut rng = XorShift::new(0x1234_5678);
        for _ in 0..5000 {
            let len = (rng.next() as usize % 256) + (rng.next() as usize % 256);
            let mut buf = Vec::with_capacity(len.min(4096));
            for _ in 0..buf.capacity() {
                buf.push(rng.next());
            }
            let _ = parse(&buf);
            let trunc = rng.next() as usize % buf.len().max(1);
            if !buf.is_empty() {
                let _ = parse(&buf[..trunc.min(buf.len())]);
            }
        }
    }
}