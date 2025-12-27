//! TDS server message enums.

use bytes::BytesMut;

use crate::tds::codec::{
    Packet, PreloginMessage, RpcOption, RpcProcId, TokenColMetaData, TokenDone, TokenEnvChange,
    TokenError, TokenFeatureExtAck, TokenInfo, TokenLoginAck, TokenReturnValue, TokenRow,
    TokenSspi,
};
use enumflags2::BitFlags;

/// Frontend messages understood by the server.
#[derive(Debug)]
pub enum TdsFrontendMessage {
    Prelogin(PreloginMessage),
    Login(crate::tds::codec::LoginMessage<'static>),
    SqlBatch(String),
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
}

/// Token stream elements produced by the server.
#[derive(Debug)]
pub enum BackendToken {
    LoginAck(TokenLoginAck),
    EnvChange(TokenEnvChange),
    Info(TokenInfo),
    Error(TokenError),
    FeatureExtAck(TokenFeatureExtAck),
    ColMetaData(TokenColMetaData<'static>),
    Row(TokenRow<'static>),
    Done(TokenDone),
    DoneProc(TokenDone),
    DoneInProc(TokenDone),
    ReturnStatus(u32),
    ReturnValue(TokenReturnValue),
    Sspi(TokenSspi),
}

/// Backend messages emitted by the server.
#[derive(Debug)]
pub enum TdsBackendMessage {
    Prelogin(PreloginMessage),
    Token(BackendToken),
    Tokens(Vec<BackendToken>),
    TokenBytes(BytesMut),
    Packet(Packet),
}
