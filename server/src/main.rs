//! proton-mail-mcp: MCP server for a Proton Mail Bridge mailbox (read, organize, drafts).
//!
//!   proton-mail-mcp              serve MCP on LISTEN_ADDR (default 0.0.0.0:8080)
//!   proton-mail-mcp fingerprint  print the SHA-256 of Bridge's TLS certificate, then exit
//!
//! Settings come from the environment. Secrets can instead be read from a file named by the
//! same variable with a _FILE suffix (MCP_TOKEN_FILE, IMAP_PASSWORD_FILE).
//!   MCP_TOKEN         bearer token clients must send (at least 32 characters)
//!   IMAP_USER         Bridge IMAP username
//!   IMAP_PASSWORD     Bridge-generated password (not the Proton account password)
//!   IMAP_CERT_SHA256  Bridge certificate fingerprint from the `fingerprint` subcommand
//!   IMAP_HOST         default "bridge";  IMAP_PORT  default 11143
//!   AUDIT_LOG         append-only log of every change, default /audit/audit.log. If it cannot be
//!                     opened, the server still reads mail but refuses every change.
//!   DRAFT_FROM        From address for drafts, default IMAP_USER
#![forbid(unsafe_code)]

use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use proton_mail_mcp::imap::{self, Session};
use proton_mail_mcp::audit::{self, AuditLog};
use proton_mail_mcp::mcp::{Backend, Server};
use proton_mail_mcp::write::{self, DraftContext, WriteOp};
use proton_mail_mcp::tls::{self, CertPin, TlsStream};
use proton_mail_mcp::{http, tools};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CONNECTIONS: usize = 8;

struct ImapBackend {
    host: String,
    port: u16,
    user: String,
    password: String,
    pin: [u8; 32],
    audit: Option<AuditLog>,
    draft_from: String,
}

impl ImapBackend {
    /// One IMAP session per tool call: connect, STARTTLS, log in, run, log out.
    fn with_session<T>(
        &self,
        f: impl FnOnce(&mut Session<TlsStream>) -> Result<T, imap::Error>,
    ) -> Result<T, String> {
        let conn = tls::connect(&self.host, self.port, CertPin::Sha256(self.pin), CONNECT_TIMEOUT)
            .map_err(|e| describe(&e))?;
        let mut session = Session::login(conn, &self.user, &self.password).map_err(|e| describe(&e))?;
        let out = f(&mut session).map_err(|e| describe(&e));
        session.logout();
        out
    }
}

impl Backend for ImapBackend {
    fn list_mailboxes(&self) -> Result<String, String> {
        self.with_session(tools::list_mailboxes)
    }
    fn list_messages(&self, args: &tools::ListArgs, fence_id: &str) -> Result<String, String> {
        self.with_session(|s| tools::list_messages(s, args, fence_id))
    }
    fn get_message(&self, mailbox: &str, uid: u32, max_chars: u32, fence_id: &str) -> Result<String, String> {
        self.with_session(|s| tools::get_message(s, mailbox, uid, max_chars, fence_id))
    }
    fn get_attachment(&self, mailbox: &str, uid: u32, index: u32, max_chars: u32, fence_id: &str) -> Result<String, String> {
        self.with_session(|s| write::get_attachment(s, mailbox, uid, index, max_chars, fence_id))
    }
    fn write(&self, op: &WriteOp, op_id: &str) -> Result<String, String> {
        let Some(audit) = &self.audit else {
            return Err("Changes are disabled because the audit log is unavailable.".into());
        };
        audit.begin(op_id, op.tool(), op.audit_args())?;
        let date = audit::rfc5322_date(audit::now_unix());
        let domain = self.draft_from.rsplit_once('@').map(|(_, d)| d).unwrap_or("localhost");
        let message_id = format!("<{op_id}@{domain}>");
        let ctx = DraftContext { from: &self.draft_from, date: &date, message_id: &message_id };
        let result = self.with_session(|s| Ok(write::execute(s, op, &ctx))).and_then(|r| r);
        match &result {
            Ok(out) => audit.finish(op_id, op.tool(), Ok(&out.detail)),
            Err(e) => audit.finish(op_id, op.tool(), Err(e)),
        }
        result.map(|out| out.text)
    }
}

/// Errors shown to the agent. They never contain credentials (imap::Error doesn't carry them).
fn describe(e: &imap::Error) -> String {
    match e {
        imap::Error::Io(_) => "Could not reach Proton Bridge.".into(),
        imap::Error::Protocol(_) => "Unexpected reply from Proton Bridge.".into(),
        imap::Error::Server(m) => format!("Proton Bridge refused the request: {m}"),
        imap::Error::InvalidArgument(m) => format!("Invalid argument: {m}"),
    }
}

fn setting(name: &str) -> Result<String, String> {
    if let Ok(path) = std::env::var(format!("{name}_FILE")) {
        return std::fs::read_to_string(&path)
            .map(|s| s.trim().to_string())
            .map_err(|_| format!("{name}_FILE could not be read"));
    }
    std::env::var(name).map_err(|_| format!("{name} is not set"))
}

fn setting_or(name: &str, default: &str) -> String {
    std::env::var(name).unwrap_or_else(|_| default.to_string())
}

fn imap_target() -> Result<(String, u16), String> {
    let host = setting_or("IMAP_HOST", "bridge");
    let port = setting_or("IMAP_PORT", "11143").parse().map_err(|_| "IMAP_PORT must be a port number")?;
    Ok((host, port))
}

fn serve() -> Result<(), String> {
    let token = setting("MCP_TOKEN")?;
    if token.len() < 32 || !token.bytes().all(|b| b.is_ascii_graphic()) {
        return Err("MCP_TOKEN must be at least 32 printable characters with no spaces".into());
    }
    let (host, port) = imap_target()?;
    let user = setting("IMAP_USER")?;
    let audit_path = setting_or("AUDIT_LOG", "/audit/audit.log");
    let audit = match AuditLog::open(std::path::Path::new(&audit_path)) {
        Ok(a) => Some(a),
        Err(e) => {
            eprintln!("warning: audit log {audit_path} unavailable ({e}); changes are disabled");
            None
        }
    };
    let backend = ImapBackend {
        host,
        port,
        draft_from: setting_or("DRAFT_FROM", &user),
        user,
        audit,
        password: setting("IMAP_PASSWORD")?,
        pin: tls::parse_fingerprint(&setting("IMAP_CERT_SHA256")?)
            .map_err(|e| format!("IMAP_CERT_SHA256: {e}"))?,
    };
    let addr = setting_or("LISTEN_ADDR", "0.0.0.0:8080");
    let server = Server::new(&token, backend);
    eprintln!("proton-mail-mcp {} listening on {addr}", env!("CARGO_PKG_VERSION"));
    http::serve(&addr, MAX_CONNECTIONS, move |req| server.handle(req)).map_err(|e| format!("listen on {addr}: {e}"))
}

fn fingerprint() -> Result<(), String> {
    let (host, port) = imap_target()?;
    let slot = Arc::new(Mutex::new(None));
    let conn = tls::connect(&host, port, CertPin::Record(slot.clone()), CONNECT_TIMEOUT)
        .map_err(|e| format!("TLS connection to {host}:{port} failed: {e}"))?;
    drop(conn); // never logs in
    let fp = slot.lock().map_err(|_| "internal error")?.ok_or("server sent no certificate")?;
    println!("{}", tls::fingerprint_hex(&fp));
    Ok(())
}

fn main() -> ExitCode {
    let result = match std::env::args().nth(1).as_deref() {
        None | Some("serve") => serve(),
        Some("fingerprint") => fingerprint(),
        Some("--version") => {
            println!("proton-mail-mcp {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Some(_) => Err("usage: proton-mail-mcp [serve | fingerprint | --version]".into()),
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}
