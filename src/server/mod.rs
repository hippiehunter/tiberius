//! Runtime-agnostic TDS server scaffolding.
//!
//! This module mirrors the structure used in pgwire-smol, but is tailored
//! for TDS and intended to live inside tiberius.

pub mod backend;
pub mod codec;
pub mod connection;
pub mod handler;
pub mod messages;
pub mod response;
pub mod server;
pub mod state;
pub mod tls;

pub use backend::{NetBackend, NetListener, NetStream, NetStreamExt};
pub use codec::TdsCodec;
pub use connection::TdsConnection;
pub use handler::{
    AttentionHandler, AuthHandler, BulkLoadHandler, ErrorHandler, RpcHandler, SqlBatchHandler,
    TdsClientInfo, TdsServerHandlers,
};
pub use messages::{BackendToken, RpcMessage, TdsBackendMessage, TdsFrontendMessage};
pub use response::ResultSetWriter;
pub use server::process_connection;
pub use state::TdsConnectionState;
pub use tls::{NoTls, TlsAccept, TlsStream};
#[cfg(feature = "server-rustls")]
pub use tls::RustlsAcceptor;
