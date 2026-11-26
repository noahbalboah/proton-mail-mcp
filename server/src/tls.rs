//! STARTTLS upgrade with end-entity SHA-256 pinning.
//!
//! Bridge presents a self-signed certificate, so the verifier ignores the hostname and the
//! chain on purpose. Handshake signatures are still checked with the ring provider.

use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, ClientConnection, DigitallySignedStruct, SignatureScheme, StreamOwned};

use crate::imap::{self, Error};

/// How to treat the bridge certificate.
pub enum CertPin {
    /// Accept only this SHA-256 of the end-entity certificate DER.
    Sha256([u8; 32]),
    /// Record the fingerprint and accept. Used by the fingerprint subcommand, which never logs in.
    Record(Arc<Mutex<Option<[u8; 32]>>>),
}

impl std::fmt::Debug for CertPin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CertPin::Sha256(pin) => f.debug_tuple("Sha256").field(pin).finish(),
            CertPin::Record(_) => f.write_str("Record(..)"),
        }
    }
}

pub type TlsStream = StreamOwned<ClientConnection, TcpStream>;

const IO_TIMEOUT: Duration = Duration::from_secs(60);

/// Connect to Proton Bridge, read the greeting, upgrade with STARTTLS, and return a `Conn`
/// positioned for `imap::Session::login`. No second greeting is read.
pub fn connect(
    host: &str,
    port: u16,
    pin: CertPin,
    timeout: Duration,
) -> Result<imap::Conn<TlsStream>, Error> {
    let tcp = connect_tcp(host, port, timeout)?;
    tcp.set_read_timeout(Some(IO_TIMEOUT))?;
    tcp.set_write_timeout(Some(IO_TIMEOUT))?;

    let mut conn = imap::Conn::new(tcp);
    conn.read_greeting()?;
    conn.command("STARTTLS")?;
    // Refuses the upgrade when the OK line had extra buffered bytes after it.
    let tcp = conn.into_inner()?;

    let server_name = server_name_for(host)?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let schemes = provider.signature_verification_algorithms;
    let verifier = Arc::new(PinVerifier { pin, schemes });
    let config = ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
        .map_err(|err| Error::Protocol(format!("tls config: {err}")))?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    let mut tls_conn = ClientConnection::new(Arc::new(config), server_name)
        .map_err(|err| Error::Protocol(format!("tls setup: {err}")))?;
    // Finish the handshake here, so a certificate that doesn't match the pin fails in connect()
    // rather than at the first command, and the fingerprint subcommand sees the certificate.
    let mut tcp = tcp;
    while tls_conn.is_handshaking() {
        tls_conn
            .complete_io(&mut tcp)
            .map_err(|err| Error::Protocol(format!("tls handshake: {err}")))?;
    }
    Ok(imap::Conn::new(StreamOwned::new(tls_conn, tcp)))
}

fn connect_tcp(host: &str, port: u16, timeout: Duration) -> Result<TcpStream, Error> {
    let mut last_err: Option<Error> = None;
    let mut connected = None;
    for addr in (host, port).to_socket_addrs()? {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(stream) => {
                connected = Some(stream);
                break;
            }
            Err(err) => last_err = Some(Error::Io(err)),
        }
    }
    match connected {
        Some(stream) => Ok(stream),
        None => Err(match last_err {
            Some(err) => err,
            None => Error::Protocol("no addresses resolved".to_string()),
        }),
    }
}

fn server_name_for(host: &str) -> Result<ServerName<'static>, Error> {
    let name = ServerName::try_from(host)
        .map_err(|_| Error::InvalidArgument("invalid server name".to_string()))?;
    Ok(name.to_owned())
}

/// 64 hex digits, optional `:` separators, any case.
pub fn parse_fingerprint(s: &str) -> Result<[u8; 32], String> {
    let mut hex = [0u8; 64];
    let mut count = 0usize;
    for byte in s.bytes() {
        if byte == b':' {
            continue;
        }
        if !byte.is_ascii_hexdigit() {
            return Err("invalid fingerprint".to_string());
        }
        if count >= 64 {
            return Err("invalid fingerprint".to_string());
        }
        hex[count] = byte;
        count = count.saturating_add(1);
    }
    if count != 64 {
        return Err("invalid fingerprint".to_string());
    }
    let mut out = [0u8; 32];
    let mut i = 0usize;
    while i < 32 {
        let hi = hex_val(hex[i * 2])?;
        let lo = hex_val(hex[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
        i = i.saturating_add(1);
    }
    Ok(out)
}

fn hex_val(byte: u8) -> Result<u8, String> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err("invalid fingerprint".to_string()),
    }
}

/// Lowercase, colon-separated SHA-256.
pub fn fingerprint_hex(fp: &[u8; 32]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::new();
    let _ = out.try_reserve(95);
    for (i, byte) in fp.iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        let hi = usize::from(byte >> 4);
        let lo = usize::from(byte & 0x0f);
        if let Some(c) = HEX.get(hi).copied() {
            out.push(char::from(c));
        }
        if let Some(c) = HEX.get(lo).copied() {
            out.push(char::from(c));
        }
    }
    out
}

#[derive(Debug)]
struct PinVerifier {
    pin: CertPin,
    schemes: rustls::crypto::WebPkiSupportedAlgorithms,
}

impl ServerCertVerifier for PinVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let fp = match sha256_fp(end_entity.as_ref()) {
            Some(fp) => fp,
            None => {
                return Err(rustls::Error::InvalidCertificate(
                    rustls::CertificateError::BadEncoding,
                ));
            }
        };
        match &self.pin {
            CertPin::Sha256(pin) => {
                if ct_eq_32(&fp, pin) {
                    Ok(ServerCertVerified::assertion())
                } else {
                    Err(rustls::Error::InvalidCertificate(
                        rustls::CertificateError::ApplicationVerificationFailure,
                    ))
                }
            }
            CertPin::Record(slot) => {
                let mut guard = match slot.lock() {
                    Ok(guard) => guard,
                    Err(poisoned) => poisoned.into_inner(),
                };
                *guard = Some(fp);
                Ok(ServerCertVerified::assertion())
            }
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(message, cert, dss, &self.schemes)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(message, cert, dss, &self.schemes)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.schemes.supported_schemes()
    }
}

fn sha256_fp(data: &[u8]) -> Option<[u8; 32]> {
    let digest = ring::digest::digest(&ring::digest::SHA256, data);
    let bytes = digest.as_ref();
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    for (slot, byte) in out.iter_mut().zip(bytes.iter()) {
        *slot = *byte;
    }
    Some(out)
}

fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    #[allow(deprecated)]
    let cmp = ring::constant_time::verify_slices_are_equal(a, b);
    cmp.is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_fp() -> [u8; 32] {
        let mut fp = [0u8; 32];
        for (i, byte) in fp.iter_mut().enumerate() {
            *byte = u8::try_from(i).unwrap_or(0);
        }
        fp
    }

    #[test]
    fn fingerprint_parse_and_format() {
        let fp = sample_fp();
        let hex = fingerprint_hex(&fp);
        assert_eq!(
            hex,
            "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f"
        );
        assert_eq!(parse_fingerprint(&hex).unwrap(), fp);
        assert_eq!(parse_fingerprint(&hex.to_ascii_uppercase()).unwrap(), fp);
        let plain: String = hex.chars().filter(|c| *c != ':').collect();
        assert_eq!(plain.len(), 64);
        assert_eq!(parse_fingerprint(&plain).unwrap(), fp);
        assert_eq!(parse_fingerprint(&plain.to_ascii_uppercase()).unwrap(), fp);
        assert_eq!(parse_fingerprint(&format!(":{hex}:")).unwrap(), fp);

        assert!(parse_fingerprint("").is_err());
        assert!(parse_fingerprint("abcd").is_err());
        assert!(parse_fingerprint(&plain[..63]).is_err());
        assert!(parse_fingerprint(&format!("{plain}aa")).is_err());
        assert!(parse_fingerprint(&plain.replace('a', "g")).is_err());
        assert!(parse_fingerprint(&format!("{plain} ")).is_err());
        assert!(parse_fingerprint("zz").is_err());
    }

    fn verifier(pin: CertPin) -> PinVerifier {
        let provider = rustls::crypto::ring::default_provider();
        PinVerifier {
            pin,
            schemes: provider.signature_verification_algorithms,
        }
    }

    fn now() -> UnixTime {
        UnixTime::since_unix_epoch(Duration::from_secs(1_700_000_000))
    }

    #[test]
    fn verifier_accepts_pinned_der_and_rejects_a_different_one() {
        let der = b"not-a-real-certificate-just-der-bytes".to_vec();
        let fp = sha256_fp(&der).unwrap();
        let pinned = verifier(CertPin::Sha256(fp));
        let cert = CertificateDer::from(der);
        let other = CertificateDer::from(b"different-der".to_vec());
        let dns = ServerName::try_from("bridge.local").unwrap().to_owned();
        let ip = ServerName::try_from("127.0.0.1").unwrap().to_owned();
        let extra = [CertificateDer::from(b"intermediate".to_vec())];

        assert!(pinned
            .verify_server_cert(&cert, &extra, &dns, b"ocsp", now())
            .is_ok());
        assert!(pinned
            .verify_server_cert(&cert, &[], &ip, b"", now())
            .is_ok());
        assert!(pinned
            .verify_server_cert(&other, &[], &dns, b"", now())
            .is_err());

        let mut flipped = fp;
        flipped[0] ^= 0xff;
        let wrong = verifier(CertPin::Sha256(flipped));
        assert!(wrong
            .verify_server_cert(&cert, &[], &dns, b"", now())
            .is_err());

        assert!(!pinned.supported_verify_schemes().is_empty());
    }

    #[test]
    fn record_pin_stores_the_fingerprint_and_accepts() {
        let der = b"record-me".to_vec();
        let expected = sha256_fp(&der).unwrap();
        let slot = Arc::new(Mutex::new(None));
        let recorded = verifier(CertPin::Record(Arc::clone(&slot)));
        let cert = CertificateDer::from(der);
        let name = ServerName::try_from("::1").unwrap().to_owned();
        recorded
            .verify_server_cert(&cert, &[], &name, b"", now())
            .unwrap();
        let stored = match slot.lock() {
            Ok(guard) => *guard,
            Err(poisoned) => *poisoned.into_inner(),
        };
        assert_eq!(stored, Some(expected));
    }

    /// Live check against a running Bridge. Opt in with
    /// PMM_LIVE_TLS=host:port PMM_LIVE_PIN=<fingerprint> cargo test -- --ignored live_
    #[test]
    #[ignore]
    fn live_pin_accepts_match_and_rejects_mismatch() {
        let (Ok(target), Ok(pin)) = (std::env::var("PMM_LIVE_TLS"), std::env::var("PMM_LIVE_PIN")) else {
            panic!("set PMM_LIVE_TLS and PMM_LIVE_PIN");
        };
        let (host, port) = target.rsplit_once(':').expect("host:port");
        let port: u16 = port.parse().expect("port");
        let good = parse_fingerprint(&pin).expect("pin");
        let t = Duration::from_secs(5);
        assert!(connect(host, port, CertPin::Sha256(good), t).is_ok(), "matching pin must connect");
        let mut bad = good;
        bad[0] ^= 1;
        assert!(connect(host, port, CertPin::Sha256(bad), t).is_err(), "wrong pin must be refused");
    }

    #[test]
    fn server_name_accepts_dns_and_ip() {
        assert!(server_name_for("bridge.local").is_ok());
        assert!(server_name_for("127.0.0.1").is_ok());
        assert!(server_name_for("::1").is_ok());
        assert!(server_name_for("bad host").is_err());
        assert!(server_name_for("").is_err());
    }
}
