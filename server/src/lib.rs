//! MCP server for a Proton Mail Bridge mailbox. See docs/CONTRACT.md.
#![forbid(unsafe_code)]

pub mod audit;
pub mod draft;
pub mod http;
pub mod imap;
pub mod inflate;
pub mod json;
pub mod mcp;
pub mod security;
pub mod mime;
pub mod tls;
pub mod tools;
pub mod write;
