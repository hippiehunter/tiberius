//! TDS wire protocol codec for the server.

use bytes::BytesMut;

use crate::server::messages::{RpcMessage, TdsBackendMessage, TdsFrontendMessage};
use crate::server::state::TdsConnectionState;
use crate::tds::codec::{
    ColumnData, Decode, Encode, LoginMessage, Packet, PacketCodec, PacketType, PreloginMessage,
    RpcProcId, RpcStatus, TypeInfo, ALL_HEADERS_LEN_TX,
};
use crate::tds::Context;
use crate::SqlReadBytes;
use asynchronous_codec::Decoder;
use crate::{Error, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use enumflags2::BitFlags;
use futures_util::io::AsyncRead;
use std::io::Cursor;
use std::pin::Pin;
use std::task::Poll;

/// TDS wire protocol codec.
///
/// This replaces a tokio_util Framed codec and is designed to work with
/// any async I/O abstraction.
pub struct TdsCodec {
    packet_codec: PacketCodec,
    pending_type: Option<PacketType>,
    pending_payload: BytesMut,
}

impl Default for TdsCodec {
    fn default() -> Self {
        Self::new()
    }
}

impl TdsCodec {
    /// Create a new codec instance.
    pub fn new() -> Self {
        Self {
            packet_codec: PacketCodec,
            pending_type: None,
            pending_payload: BytesMut::new(),
        }
    }

    /// Decode a frontend message from the buffer.
    pub fn decode(
        &mut self,
        buf: &mut BytesMut,
        _state: TdsConnectionState,
    ) -> Result<Option<TdsFrontendMessage>> {
        let Some(packet) = self.packet_codec.decode(buf)? else {
            return Ok(None);
        };

        let is_last = packet.is_last();
        let (header, payload) = packet.into_parts();

        let payload = match self.pending_type {
            None if is_last => payload,
            None => {
                self.pending_type = Some(header.r#type());
                self.pending_payload = payload;
                return Ok(None);
            }
            Some(pending) => {
                if pending != header.r#type() {
                    return Err(Error::Protocol("tds: packet type mismatch".into()));
                }
                self.pending_payload.extend_from_slice(payload.as_ref());
                if !is_last {
                    return Ok(None);
                }
                self.pending_type = None;
                self.pending_payload.split()
            }
        };

        let message = match header.r#type() {
            PacketType::PreLogin => {
                let mut payload = payload;
                let message = PreloginMessage::decode(&mut payload)?;
                TdsFrontendMessage::Prelogin(message)
            }
            PacketType::TDSv7Login => {
                let mut payload = payload;
                let message = LoginMessage::decode(&mut payload)?;
                TdsFrontendMessage::Login(message)
            }
            PacketType::SQLBatch => {
                let mut payload = payload;
                let batch = decode_sql_batch(&mut payload)?;
                TdsFrontendMessage::SqlBatch(batch)
            }
            PacketType::Rpc => {
                let message = decode_rpc(payload)?;
                TdsFrontendMessage::Rpc(message)
            }
            PacketType::BulkLoad => TdsFrontendMessage::BulkLoad(payload),
            PacketType::AttentionSignal => TdsFrontendMessage::Attention,
            _ => TdsFrontendMessage::Packet(Packet::new(header, payload)),
        };

        Ok(Some(message))
    }

    /// Encode a backend message into the buffer.
    pub fn encode(&mut self, msg: TdsBackendMessage, buf: &mut BytesMut) -> Result<()> {
        match msg {
            TdsBackendMessage::Packet(packet) => packet.encode(buf),
            _ => Err(Error::Protocol(
                "server codec: message encoding not implemented".into(),
            )),
        }
    }
}

fn decode_sql_batch(payload: &mut BytesMut) -> Result<String> {
    let mut cursor = Cursor::new(payload);
    if cursor.get_ref().len() < 4 {
        return Err(Error::Protocol("sql batch: missing headers length".into()));
    }
    let headers_len = cursor.read_u32::<LittleEndian>()? as usize;
    if headers_len > cursor.get_ref().len() {
        return Err(Error::Protocol("sql batch: invalid headers length".into()));
    }
    cursor.set_position(headers_len as u64);

    let remaining = &cursor.get_ref()[headers_len..];
    if remaining.len() % 2 != 0 {
        return Err(Error::Protocol("sql batch: invalid utf16 length".into()));
    }
    let mut units = Vec::with_capacity(remaining.len() / 2);
    for chunk in remaining.chunks_exact(2) {
        units.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }

    String::from_utf16(&units).map_err(|_| Error::Utf16)
}

fn decode_rpc(mut payload: BytesMut) -> Result<RpcMessage> {
    let mut cursor = Cursor::new(&payload);
    if cursor.get_ref().len() < 4 {
        return Err(Error::Protocol("rpc: missing headers length".into()));
    }
    let headers_len = cursor.read_u32::<LittleEndian>()? as usize;
    if headers_len < ALL_HEADERS_LEN_TX || headers_len > cursor.get_ref().len() {
        return Err(Error::Protocol("rpc: invalid headers length".into()));
    }
    cursor.set_position(headers_len as u64);

    if (cursor.get_ref().len() as u64) < cursor.position() + 4 {
        return Err(Error::Protocol("rpc: missing proc id".into()));
    }

    let name_len_or_marker = cursor.read_u16::<LittleEndian>()?;
    let (proc_id, proc_name) = if name_len_or_marker == 0xffff {
        let id = cursor.read_u16::<LittleEndian>()?;
        (rpc_proc_id_from_u16(id), None)
    } else {
        let name_len = name_len_or_marker as usize;
        let needed = (name_len as u64) * 2;
        if (cursor.get_ref().len() as u64) < cursor.position() + needed + 2 {
            return Err(Error::Protocol("rpc: missing proc name".into()));
        }
        let mut units = Vec::with_capacity(name_len);
        for _ in 0..name_len {
            units.push(cursor.read_u16::<LittleEndian>()?);
        }
        let name = String::from_utf16(&units).map_err(|_| Error::Utf16)?;
        (None, Some(name))
    };

    let flags_raw = cursor.read_u16::<LittleEndian>()?;
    let flags = BitFlags::from_bits_truncate(flags_raw);

    let pos = cursor.position() as usize;
    let params = payload.split_off(pos);

    Ok(RpcMessage {
        proc_id,
        proc_name,
        flags,
        params,
    })
}

fn rpc_proc_id_from_u16(id: u16) -> Option<RpcProcId> {
    match id as u8 {
        2 => Some(RpcProcId::CursorOpen),
        7 => Some(RpcProcId::CursorFetch),
        9 => Some(RpcProcId::CursorClose),
        10 => Some(RpcProcId::ExecuteSQL),
        11 => Some(RpcProcId::Prepare),
        12 => Some(RpcProcId::Execute),
        13 => Some(RpcProcId::PrepExec),
        15 => Some(RpcProcId::Unprepare),
        _ => None,
    }
}

/// Decoded RPC parameter payload.
#[derive(Debug)]
pub struct DecodedRpcParam {
    pub name: String,
    pub flags: BitFlags<RpcStatus>,
    pub ty: TypeInfo,
    pub value: ColumnData<'static>,
}

/// Decode RPC parameters from a raw RPC payload.
pub async fn decode_rpc_params(params: BytesMut) -> Result<Vec<DecodedRpcParam>> {
    let mut reader = RpcParamReader::new(params);
    let mut decoded = Vec::new();

    while reader.remaining() > 0 {
        let name_len = reader.read_u8().await? as usize;
        let name = read_rpc_name(&mut reader, name_len).await?;
        let flags_raw = reader.read_u8().await?;
        let flags = BitFlags::from_bits_truncate(flags_raw);
        let ty = TypeInfo::decode(&mut reader).await?;
        let value: ColumnData<'static> = ColumnData::decode(&mut reader, &ty).await?;

        decoded.push(DecodedRpcParam {
            name,
            flags,
            ty,
            value,
        });
    }

    Ok(decoded)
}

async fn read_rpc_name<R>(reader: &mut R, len: usize) -> Result<String>
where
    R: SqlReadBytes + Unpin,
{
    if len == 0 {
        return Ok(String::new());
    }

    let mut units = Vec::with_capacity(len);
    for _ in 0..len {
        units.push(reader.read_u16_le().await?);
    }

    String::from_utf16(&units).map_err(|_| Error::Utf16)
}

struct RpcParamReader {
    buf: BytesMut,
    context: Context,
}

impl RpcParamReader {
    fn new(buf: BytesMut) -> Self {
        Self {
            buf,
            context: Context::new(),
        }
    }

    fn remaining(&self) -> usize {
        self.buf.len()
    }
}

impl AsyncRead for RpcParamReader {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        let size = buf.len();

        if this.buf.len() < size {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::UnexpectedEof,
                "rpc params: unexpected eof",
            )));
        }

        buf.copy_from_slice(this.buf.split_to(size).as_ref());
        Poll::Ready(Ok(size))
    }
}

impl SqlReadBytes for RpcParamReader {
    fn debug_buffer(&self) {}

    fn context(&self) -> &Context {
        &self.context
    }

    fn context_mut(&mut self) -> &mut Context {
        &mut self.context
    }
}
