//! Connection state for the TDS server.

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TdsConnectionState {
    AwaitingPrelogin,
    AwaitingLogin,
    AuthenticationInProgress,
    ReadyForQuery,
    BulkLoadInProgress,
    AttentionPending,
    Closed,
}
