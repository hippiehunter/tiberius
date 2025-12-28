//! TDS server message enums.

use bytes::BytesMut;

use crate::tds::codec::{
    Packet, PreloginMessage, RpcOption, RpcProcId, TokenAltMetaData, TokenAltRow, TokenColInfo,
    TokenColMetaData, TokenColName, TokenDone, TokenEnvChange, TokenError, TokenFedAuthInfo,
    TokenFeatureExtAck, TokenInfo, TokenLoginAck, TokenOrder, TokenReturnValue, TokenRow,
    TokenSessionState, TokenSspi, TokenTabName,
};
use enumflags2::BitFlags;

/// Packet status flags carried by the request.
#[derive(Debug, Clone, Copy, Default)]
pub struct RequestFlags {
    pub reset_connection: bool,
    pub reset_connection_skip_tran: bool,
}

impl RequestFlags {
    pub(crate) fn from_status_bits(bits: u8) -> Self {
        Self {
            reset_connection: (bits & crate::tds::codec::PacketStatus::ResetConnection as u8) != 0,
            reset_connection_skip_tran: (bits
                & crate::tds::codec::PacketStatus::ResetConnectionSkipTran as u8)
                != 0,
        }
    }
}

/// ALL_HEADERS metadata parsed from SQL batch / RPC requests.
#[derive(Debug, Clone, Default)]
pub struct AllHeaders {
    pub transaction_descriptor: Option<TransactionDescriptorHeader>,
    pub query_descriptor: Option<Vec<u8>>,
    pub trace_activity: Option<TraceActivityHeader>,
    pub unknown: Vec<UnknownHeader>,
}

#[derive(Debug, Clone)]
pub struct TransactionDescriptorHeader {
    pub descriptor: [u8; 8],
    pub outstanding_requests: u32,
}

#[derive(Debug, Clone)]
pub struct TraceActivityHeader {
    pub activity_id: [u8; 16],
    pub sequence_number: u32,
}

#[derive(Debug, Clone)]
pub struct UnknownHeader {
    pub header_type: u16,
    pub data: Vec<u8>,
}

/// Parsed SQL batch request.
#[derive(Debug)]
pub struct SqlBatchMessage {
    pub batch: String,
    pub headers: AllHeaders,
    pub request_flags: RequestFlags,
}

/// Frontend messages understood by the server.
#[derive(Debug)]
pub enum TdsFrontendMessage {
    Prelogin(PreloginMessage),
    Login(crate::tds::codec::LoginMessage<'static>),
    Sspi(TokenSspi),
    SqlBatch(SqlBatchMessage),
    Attention,
    BulkLoad(BytesMut),
    Rpc(RpcMessage),
    Packet(Packet),
}

#[derive(Debug)]
pub struct RpcMessage {
    pub proc_id: Option<RpcProcId>,
    pub proc_name: Option<String>,
    pub flags: BitFlags<RpcOption>,
    pub params: BytesMut,
    pub headers: AllHeaders,
    pub request_flags: RequestFlags,
}

/// Token stream elements produced by the server.
#[derive(Debug)]
pub enum BackendToken {
    LoginAck(TokenLoginAck),
    EnvChange(TokenEnvChange),
    Info(TokenInfo),
    Error(TokenError),
    FeatureExtAck(TokenFeatureExtAck),
    ColName(TokenColName),
    TabName(TokenTabName),
    ColInfo(TokenColInfo),
    ColMetaData(TokenColMetaData<'static>),
    AltMetaData(TokenAltMetaData<'static>),
    Row(TokenRow<'static>),
    NbcRow(TokenRow<'static>),
    AltRow(TokenAltRow<'static>),
    Order(TokenOrder),
    Done(TokenDone),
    DoneProc(TokenDone),
    DoneInProc(TokenDone),
    ReturnStatus(u32),
    ReturnValue(TokenReturnValue),
    SessionState(TokenSessionState),
    FedAuthInfo(TokenFedAuthInfo),
    Sspi(TokenSspi),
}

/// Backend messages emitted by the server.
#[derive(Debug)]
pub enum TdsBackendMessage {
    Prelogin(PreloginMessage),
    Token(BackendToken),
    TokenPartial(BackendToken),
    Tokens(Vec<BackendToken>),
    TokenBytes(BytesMut),
    TokenBytesPartial(BytesMut),
    Packet(Packet),
}
