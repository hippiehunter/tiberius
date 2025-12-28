//! Handler traits for the TDS server.

use std::collections::HashMap;
use std::net::SocketAddr;

use futures_util::sink::Sink;

use crate::EncryptionLevel;
use crate::server::messages::{AllHeaders, TdsBackendMessage};
use crate::server::state::TdsConnectionState;
use crate::tds::codec::FeatureLevel;
use crate::Result;

type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// Connection metadata exposed to handlers.
pub trait TdsClientInfo {
    fn socket_addr(&self) -> SocketAddr;
    fn is_secure(&self) -> bool;
    fn state(&self) -> TdsConnectionState;
    fn set_state(&mut self, state: TdsConnectionState);
    fn metadata(&self) -> &HashMap<String, String>;
    fn metadata_mut(&mut self) -> &mut HashMap<String, String>;
    fn next_packet_id(&mut self) -> u8;
    fn packet_size(&self) -> u32;
    fn set_packet_size(&mut self, size: u32);
    fn tds_version(&self) -> FeatureLevel;
    fn set_tds_version(&mut self, version: FeatureLevel);
    fn transaction_descriptor(&self) -> [u8; 8];
    fn set_transaction_descriptor(&mut self, desc: [u8; 8]);
    fn last_request_headers(&self) -> &AllHeaders;
    fn encryption(&self) -> EncryptionLevel;
    fn set_encryption(&mut self, encryption: EncryptionLevel);
    /// True if a cancel/attention has been observed.
    fn attention_pending(&self) -> bool;
    /// Clear the cancel/attention flag.
    fn clear_attention(&mut self);
    /// Poll the wire for an attention signal while inside a handler.
    fn poll_attention<'a>(&'a mut self) -> BoxFuture<'a, Result<bool>>
    where
        Self: Sized;
}

/// Authentication and handshake handling.
pub trait AuthHandler: Send + Sync {
    fn on_prelogin<'a, C>(
        &'a self,
        client: &'a mut C,
        message: crate::tds::codec::PreloginMessage,
    ) -> BoxFuture<'a, Result<()>>
    where
        C: TdsClientInfo
            + Sink<TdsBackendMessage, Error = crate::Error>
            + Unpin
            + Send
            + 'a;

    fn on_login<'a, C>(
        &'a self,
        client: &'a mut C,
        message: crate::tds::codec::LoginMessage<'static>,
    ) -> BoxFuture<'a, Result<()>>
    where
        C: TdsClientInfo
            + Sink<TdsBackendMessage, Error = crate::Error>
            + Unpin
            + Send
            + 'a;

    fn on_sspi<'a, C>(
        &'a self,
        _client: &'a mut C,
        _token: crate::tds::codec::TokenSspi,
    ) -> BoxFuture<'a, Result<()>>
    where
        C: TdsClientInfo
            + Sink<TdsBackendMessage, Error = crate::Error>
            + Unpin
            + Send
            + 'a,
    {
        Box::pin(async {
            Err(crate::Error::Protocol(
                "SSPI message not supported by this auth handler".into(),
            ))
        })
    }
}

/// SQL batch handler (simple query flow).
pub trait SqlBatchHandler: Send + Sync {
    fn on_sql_batch<'a, C>(
        &'a self,
        client: &'a mut C,
        message: crate::server::messages::SqlBatchMessage,
    ) -> BoxFuture<'a, Result<()>>
    where
        C: TdsClientInfo
            + Sink<TdsBackendMessage, Error = crate::Error>
            + Unpin
            + Send
            + 'a;
}

/// RPC handler (stored proc / parameterized flow).
pub trait RpcHandler: Send + Sync {
    fn on_rpc<'a, C>(
        &'a self,
        client: &'a mut C,
        message: crate::server::messages::RpcMessage,
    ) -> BoxFuture<'a, Result<()>>
    where
        C: TdsClientInfo
            + Sink<TdsBackendMessage, Error = crate::Error>
            + Unpin
            + Send
            + 'a;
}

/// Bulk load handler.
pub trait BulkLoadHandler: Send + Sync {
    fn on_bulk_load<'a, C>(
        &'a self,
        client: &'a mut C,
        payload: bytes::BytesMut,
    ) -> BoxFuture<'a, Result<()>>
    where
        C: TdsClientInfo
            + Sink<TdsBackendMessage, Error = crate::Error>
            + Unpin
            + Send
            + 'a;
}

/// Attention handler for cancelling in-flight requests.
pub trait AttentionHandler: Send + Sync {
    fn on_attention<'a, C>(&'a self, client: &'a mut C) -> BoxFuture<'a, Result<()>>
    where
        C: TdsClientInfo
            + Sink<TdsBackendMessage, Error = crate::Error>
            + Unpin
            + Send
            + 'a;
}

/// Error handler invoked when processing fails.
pub trait ErrorHandler: Send + Sync {
    fn on_error(&self, client: &dyn TdsClientInfo, error: &mut crate::Error);
}

/// Bundle of handlers required by the server.
pub trait TdsServerHandlers: Send + Sync {
    type Auth: AuthHandler;
    type SqlBatch: SqlBatchHandler;
    type Rpc: RpcHandler;
    type Bulk: BulkLoadHandler;
    type Attention: AttentionHandler;
    type Error: ErrorHandler;

    fn auth_handler(&self) -> &Self::Auth;
    fn sql_batch_handler(&self) -> &Self::SqlBatch;
    fn rpc_handler(&self) -> &Self::Rpc;
    fn bulk_load_handler(&self) -> &Self::Bulk;
    fn attention_handler(&self) -> &Self::Attention;
    fn error_handler(&self) -> &Self::Error;
}
