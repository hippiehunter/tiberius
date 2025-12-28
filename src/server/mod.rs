//! Runtime-agnostic TDS server scaffolding.
//!
//! This module mirrors the structure used in pgwire-smol, but is tailored
//! for TDS and intended to live inside tiberius.

pub mod backend;
pub mod auth;
pub mod codec;
pub mod connection;
pub mod handler;
pub mod messages;
pub mod response;
pub mod server;
pub mod state;
pub mod tls;

pub use backend::{NetBackend, NetListener, NetStream, NetStreamExt};
pub use auth::{
    AuthBuilder, AuthError, AuthSuccess, DefaultEnvChangeProvider, EnvChangeProvider,
    FedAuthValidator, LoginInfo, SqlAuthSource, SspiAcceptor, SspiSession, SspiStart, SspiStep,
    TdsAuthHandler,
    METADATA_APPLICATION, METADATA_DATABASE, METADATA_SERVER, METADATA_USER,
};
pub use codec::TdsCodec;
pub use connection::TdsConnection;
pub use handler::{
    AttentionHandler, AuthHandler, BulkLoadHandler, ErrorHandler, RpcHandler, SqlBatchHandler,
    TdsClientInfo, TdsServerHandlers,
};
pub use messages::{
    AllHeaders, BackendToken, RequestFlags, RpcMessage, SqlBatchMessage, TdsBackendMessage,
    TdsFrontendMessage,
};
pub use response::ResultSetWriter;
pub use server::process_connection;
pub use state::TdsConnectionState;
pub use tls::{NoTls, TlsAccept, TlsStream};
#[cfg(feature = "server-rustls")]
pub use tls::RustlsAcceptor;
#[cfg(all(unix, feature = "integrated-auth-gssapi"))]
pub use auth::gssapi::GssapiAcceptor;
