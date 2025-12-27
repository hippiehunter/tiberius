//! Handler traits for the TDS server.

use std::collections::HashMap;
use std::net::SocketAddr;

use futures_util::sink::Sink;

use crate::EncryptionLevel;
use crate::server::messages::TdsBackendMessage;
use crate::server::state::TdsConnectionState;
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
    fn transaction_descriptor(&self) -> [u8; 8];
    fn set_transaction_descriptor(&mut self, desc: [u8; 8]);
    fn encryption(&self) -> EncryptionLevel;
    fn set_encryption(&mut self, encryption: EncryptionLevel);
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
}

/// SQL batch handler (simple query flow).
pub trait SqlBatchHandler: Send + Sync {
    fn on_sql_batch<'a, C>(
        &'a self,
        client: &'a mut C,
        batch: String,
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
