//! zlib (RFC 1950) and DEFLATE (RFC 1951) decoder with output caps.

#[cfg(test)]
const DEFAULT_MAX_OUTPUT: usize = 50 * 1024 * 1024;

/// Inflate a zlib-wrapped stream (RFC 1950).
pub fn zlib_inflate(input: &[u8], max_output: usize) -> Result<Vec<u8>, String> {
    if input.len() < 2 {
        return Err("zlib: input too short".into());
    }
    let cmf = input[0];
    let flg = input[1];
    if cmf & 0x0f != 8 {
        return Err("zlib: unsupported compression method".into());
    }
  let _window = (cmf as u16 >> 4).saturating_add(8);
    let check = (u16::from(cmf) * 256 + u16::from(flg)) % 31;
    if check != 0 {
        return Err("zlib: header check failed".into());
    }
    let raw = input
        .get(2..)
        .and_then(|s| if s.len() >= 4 { Some(&s[..s.len() - 4]) } else { None })
        .ok_or_else(|| "zlib: truncated".to_string())?;
    deflate_decode(raw, max_output)
}

/// Inflate raw DEFLATE blocks (no zlib wrapper).
pub fn deflate_decode(input: &[u8], max_output: usize) -> Result<Vec<u8>, String> {
    if max_output == 0 {
        return Err("output cap is zero".into());
    }
    let mut br = BitReader::new(input);
    let mut out = Vec::new();
    loop {
        let bfinal = br.read_bits(1)? == 1;
        let btype = br.read_bits(2)?;
        match btype {
            0 => decode_stored(&mut br, &mut out, max_output)?,
            1 => decode_fixed(&mut br, &mut out, max_output)?,
            2 => decode_dynamic(&mut br, &mut out, max_output)?,
            _ => return Err("invalid block type".into()),
        }
        if bfinal {
            break;
        }
        if br.pos > input.len().saturating_add(8) {
            return Err("input overrun".into());
        }
    }
    Ok(out)
}

struct BitReader<'a> {
    data: &'a [u8],
    pos: usize,
    buf: u32,
    bits: u8,
}

impl<'a> BitReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            buf: 0,
            bits: 0,
        }
    }

    fn read_bits(&mut self, n: u8) -> Result<u32, String> {
        if n == 0 {
            return Ok(0);
        }
        if n > 15 {
            return Err("too many bits".into());
        }
        while self.bits < n {
            if self.pos >= self.data.len() {
                return Err("unexpected end of input".into());
            }
            self.buf |= u32::from(self.data[self.pos]) << self.bits;
            self.pos += 1;
            self.bits += 8;
        }
        let mask = (1u32 << n) - 1;
        let val = self.buf & mask;
        self.buf >>= n;
        self.bits -= n;
        Ok(val)
    }

    fn align_byte(&mut self) {
        let discard = self.bits % 8;
        if discard > 0 {
            let _ = self.read_bits(discard);
        } else if self.bits > 0 {
            let _ = self.read_bits(self.bits);
        }
    }
}

fn push_output(out: &mut Vec<u8>, byte: u8, max_output: usize) -> Result<(), String> {
    if out.len() >= max_output {
        return Err("output cap exceeded".into());
    }
    out.push(byte);
    Ok(())
}

fn copy_output(out: &mut Vec<u8>, dist: usize, len: usize, max_output: usize) -> Result<(), String> {
    if dist == 0 || dist > out.len() {
        return Err("invalid copy distance".into());
    }
    let start = out.len() - dist;
    for i in 0..len {
        if out.len() >= max_output {
            return Err("output cap exceeded".into());
        }
        let b = *out.get(start + (i % dist)).ok_or_else(|| "copy overrun".to_string())?;
        out.push(b);
    }
    Ok(())
}

fn decode_stored(br: &mut BitReader<'_>, out: &mut Vec<u8>, max_output: usize) -> Result<(), String> {
    br.align_byte();
    let pos = br.pos;
    if pos + 4 > br.data.len() {
        return Err("stored block header truncated".into());
    }
    let len = u16::from_le_bytes([br.data[pos], br.data[pos + 1]]);
    let nlen = u16::from_le_bytes([br.data[pos + 2], br.data[pos + 3]]);
    if len != !nlen {
        return Err("stored length mismatch".into());
    }
    br.pos = pos + 4;
    let end = br.pos.saturating_add(len as usize);
    if end > br.data.len() {
        return Err("stored data truncated".into());
    }
    if out.len().saturating_add(len as usize) > max_output {
        return Err("output cap exceeded".into());
    }
    out.extend_from_slice(br.data.get(br.pos..end).ok_or("stored slice")?);
    br.pos = end;
    Ok(())
}

const BASE_LEN: [u16; 29] = [
    3, 4, 5, 6, 7, 8, 9, 10, 11, 13, 15, 17, 19, 23, 27, 31, 35, 43, 51, 59, 67, 83, 99, 115,
    131, 163, 195, 227, 258,
];
const EXTRA_LEN: [u8; 29] = [
    0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3, 4, 4, 4, 4, 5, 5, 5, 5, 0,
];
const BASE_DIST: [u16; 30] = [
    1, 2, 3, 4, 5, 7, 9, 13, 17, 25, 33, 49, 65, 97, 129, 193, 257, 385, 513, 769, 1025, 1537,
    2049, 3073, 4097, 6145, 8193, 12289, 16385, 24577,
];
const EXTRA_DIST: [u8; 30] = [
    0, 0, 0, 0, 1, 1, 2, 2, 3, 3, 4, 4, 5, 5, 6, 6, 7, 7, 8, 8, 9, 9, 10, 10, 11, 11, 12, 12, 13,
    13,
];

struct Huffman {
    max_bits: u8,
    table: Vec<(u16, u8, u16)>,
}

impl Huffman {
    fn fixed_literal() -> Self {
        let mut counts = [0u16; 16];
        for len in FIXED_LITERAL_LENGTHS {
            if len > 0 {
                counts[len as usize] += 1;
            }
        }
        let mut symbols: Vec<u16> = (0..288).collect();
        symbols.sort_by_key(|&s| FIXED_LITERAL_LENGTHS[s as usize]);
        Self::from_lengths(&counts, &symbols, 15)
    }

    fn fixed_dist() -> Self {
        let mut counts = [0u16; 16];
        for len in FIXED_DIST_LENGTHS {
            counts[len as usize] += 1;
        }
        let mut symbols: Vec<u16> = (0..32).collect();
        symbols.sort_by_key(|&s| FIXED_DIST_LENGTHS[s as usize]);
        Self::from_lengths(&counts, &symbols, 15)
    }

    fn from_lengths(counts: &[u16; 16], symbols: &[u16], max_bits: u8) -> Self {
        let mut table = Vec::new();
        let mut code = 0u16;
        let mut len_idx = 1usize;
        let mut sym_idx = 0usize;
        while len_idx <= max_bits as usize {
            let n = counts[len_idx];
            for _ in 0..n {
                if sym_idx >= symbols.len() {
                    break;
                }
                let sym = symbols[sym_idx];
                sym_idx += 1;
                table.push((code, len_idx as u8, sym));
                code = code.wrapping_add(1);
            }
            code = code.wrapping_shl(1);
            len_idx += 1;
        }
        Self { max_bits, table }
    }

    fn decode(&self, br: &mut BitReader<'_>) -> Result<u16, String> {
        let mut code = 0u32;
        for len in 1..=self.max_bits {
            let bit = br.read_bits(1)?;
            code = (code << 1) | bit;
            let code_u16 = code as u16;
            for &(c, l, sym) in &self.table {
                if l == len && c == code_u16 {
                    return Ok(sym);
                }
            }
        }
        Err("invalid huffman code".into())
    }
}

const FIXED_LITERAL_LENGTHS: [u8; 288] = {
    let mut t = [0u8; 288];
    let mut i = 0;
    while i <= 143 {
        t[i] = 8;
        i += 1;
    }
    while i <= 255 {
        t[i] = 9;
        i += 1;
    }
    while i <= 279 {
        t[i] = 7;
        i += 1;
    }
    while i <= 287 {
        t[i] = 8;
        i += 1;
    }
    t
};

const FIXED_DIST_LENGTHS: [u8; 32] = [5u8; 32];

const CODE_LENGTH_ORDER: [u8; 19] = [
    16, 17, 18, 0, 8, 7, 9, 6, 10, 5, 11, 4, 12, 3, 13, 2, 14, 1, 15,
];

fn decode_huffman_block(
    br: &mut BitReader<'_>,
    lit: &Huffman,
    dist: &Huffman,
    out: &mut Vec<u8>,
    max_output: usize,
) -> Result<(), String> {
    const MAX_ITER: usize = 16_777_216;
    for _ in 0..MAX_ITER {
        let sym = lit.decode(br)?;
        if sym < 256 {
            push_output(out, sym as u8, max_output)?;
        } else if sym == 256 {
            return Ok(());
        } else {
            let li = sym - 257;
            if li >= 29 {
                return Err("invalid length symbol".into());
            }
            let extra = EXTRA_LEN[li as usize];
            let bits = if extra > 0 {
                br.read_bits(extra)?
            } else {
                0
            };
            let len = usize::from(BASE_LEN[li as usize]) + bits as usize;
            let dsym = dist.decode(br)?;
            if dsym >= 30 {
                return Err("invalid distance symbol".into());
            }
            let dex = EXTRA_DIST[dsym as usize];
            let dbits = if dex > 0 {
                br.read_bits(dex)?
            } else {
                0
            };
            let distance = usize::from(BASE_DIST[dsym as usize]) + dbits as usize;
            if distance > 32_768 {
                return Err("distance too large".into());
            }
            copy_output(out, distance, len, max_output)?;
        }
    }
    Err("block iteration limit".into())
}

fn decode_fixed(br: &mut BitReader<'_>, out: &mut Vec<u8>, max_output: usize) -> Result<(), String> {
    let lit = Huffman::fixed_literal();
    let dist = Huffman::fixed_dist();
    decode_huffman_block(br, &lit, &dist, out, max_output)
}

fn decode_dynamic(br: &mut BitReader<'_>, out: &mut Vec<u8>, max_output: usize) -> Result<(), String> {
    let hlit = br.read_bits(5)? + 257;
    let hdist = br.read_bits(5)? + 1;
    let hclen = br.read_bits(4)? + 4;
    let mut cl_lengths = [0u8; 19];
    for i in 0..hclen {
        cl_lengths[CODE_LENGTH_ORDER[i as usize] as usize] = br.read_bits(3)? as u8;
    }
    let mut counts = [0u16; 16];
    for &l in &cl_lengths {
        if l > 0 {
            counts[l as usize] += 1;
        }
    }
    let mut syms: Vec<u16> = (0..19).filter(|&s| cl_lengths[s as usize] > 0).collect();
    syms.sort_by_key(|&s| cl_lengths[s as usize]);
    let cl = Huffman::from_lengths(&counts, &syms, 7);

    let total = (hlit + hdist) as usize;
    let mut lengths = vec![0u8; total];
    let mut i = 0;
    while i < total {
        let sym = cl.decode(br)?;
        if sym < 16 {
            lengths[i] = sym as u8;
            i += 1;
        } else if sym == 16 {
            if i == 0 {
                return Err("repeat16 at start".into());
            }
            let rep = br.read_bits(2)? + 3;
            let prev = lengths[i - 1];
            for _ in 0..rep {
                if i >= total {
                    break;
                }
                lengths[i] = prev;
                i += 1;
            }
        } else if sym == 17 {
            let rep = br.read_bits(3)? + 3;
            for _ in 0..rep {
                if i >= total {
                    break;
                }
                lengths[i] = 0;
                i += 1;
            }
        } else if sym == 18 {
            let rep = br.read_bits(7)? + 11;
            for _ in 0..rep {
                if i >= total {
                    break;
                }
                lengths[i] = 0;
                i += 1;
            }
        } else {
            return Err("invalid code length symbol".into());
        }
    }

    let lit_lengths = &lengths[..hlit as usize];
    let dist_lengths = &lengths[hlit as usize..];

    fn build_tree(lengths: &[u8], max_bits: u8) -> Result<Huffman, String> {
        let mut counts = [0u16; 16];
        for &l in lengths {
            if l > max_bits {
                return Err("code too long".into());
            }
            if l > 0 {
                counts[l as usize] += 1;
            }
        }
        let mut symbols: Vec<u16> = (0..lengths.len() as u16).collect();
        symbols.retain(|&s| lengths[s as usize] > 0);
        symbols.sort_by_key(|&s| lengths[s as usize]);
        Ok(Huffman::from_lengths(&counts, &symbols, max_bits))
    }

    let lit = build_tree(lit_lengths, 15)?;
    let dist = build_tree(dist_lengths, 15)?;
    decode_huffman_block(br, &lit, &dist, out, max_output)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zlib_hello() {
        // python3 -c "import zlib; print(zlib.compress(b'hello').hex())"
        let bytes: [u8; 13] = [120, 156, 203, 72, 205, 201, 201, 7, 0, 6, 44, 2, 21];
        let out = zlib_inflate(&bytes, DEFAULT_MAX_OUTPUT).expect("hello");
        assert_eq!(out, b"hello");
    }

    #[test]
    fn stored_block_direct() {
        // Stored block: BFINAL=1, BTYPE=00, len=5, ~len, "hello"
        let data: [u8; 10] = [0x01, 0x05, 0x00, 0xfa, 0xff, b'h', b'e', b'l', b'l', b'o'];
        let out = deflate_decode(&data, 1024).expect("stored");
        assert_eq!(out, b"hello");
    }

    #[test]
    fn fixed_huffman_zlib() {
        let bytes: [u8; 11] = [120, 1, 75, 76, 74, 6, 0, 2, 77, 1, 39];
        let out = zlib_inflate(&bytes, DEFAULT_MAX_OUTPUT).expect("fixed");
        assert_eq!(out, b"abc");
    }

    #[test]
    fn dynamic_block() {
        let expected: Vec<u8> = (0u8..50u8).collect();
        let compressed: [u8; 58] = [
            120, 156, 99, 96, 100, 98, 102, 97, 101, 99, 231, 224, 228, 226, 230, 225, 229, 227,
            23, 16, 20, 18, 22, 17, 21, 19, 151, 144, 148, 146, 150, 145, 149, 147, 87, 80, 84, 82,
            86, 81, 85, 83, 215, 208, 212, 210, 214, 209, 213, 211, 55, 48, 4, 0, 81, 139, 4, 202,
        ];
        let out = zlib_inflate(&compressed, DEFAULT_MAX_OUTPUT).expect("dynamic");
        assert_eq!(out, expected);
    }

    fn python_zlib_compress(data: &[u8]) -> Vec<u8> {
        let out = std::process::Command::new("python3")
            .args(["-c", "import zlib,sys; sys.stdout.buffer.write(zlib.compress(bytes(sys.stdin.buffer.read())))"])
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .and_then(|mut child| {
                use std::io::Write;
                if let Some(mut stdin) = child.stdin.take() {
                    let _ = stdin.write_all(data);
                }
                child.wait_with_output()
            })
            .expect("python");
        out.stdout
    }

    #[test]
    fn truncated_input_errors() {
        let err = zlib_inflate(&[0x78, 0x9c], 1024).unwrap_err();
        assert!(!err.is_empty());
    }

    #[test]
    fn output_cap() {
        let big: Vec<u8> = vec![0u8; 100_000];
        let compressed = python_zlib_compress(&big);
        let err = zlib_inflate(&compressed, 1000).unwrap_err();
        assert!(err.contains("cap"));
    }

    #[test]
    fn bad_distance() {
        // Invalid deflate bitstream with bogus reference
        let data: [u8; 4] = [0x03, 0xff, 0xff, 0xff];
        let _ = deflate_decode(&data, 1024);
    }
}