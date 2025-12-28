//! TDS wire protocol codec for the server.

use bytes::{Buf, BytesMut};

use crate::server::messages::{
    AllHeaders, RequestFlags, RpcMessage, SqlBatchMessage, TdsBackendMessage,
    TdsFrontendMessage, TraceActivityHeader, TransactionDescriptorHeader, UnknownHeader,
};
use crate::server::state::TdsConnectionState;
use crate::tds::codec::{
    ColumnData, Decode, Encode, LoginMessage, Packet, PacketCodec, PacketType, PreloginMessage,
    RpcProcId, RpcStatus, TokenSspi, TokenType, TypeInfo,
};
use crate::tds::Context;
use crate::SqlReadBytes;
use asynchronous_codec::Decoder;
use crate::{Error, Result};
use byteorder::{LittleEndian, ReadBytesExt};
use enumflags2::BitFlags;
use futures_util::io::AsyncRead;
use std::io::{Cursor, Read};
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
    pending_status: Option<u8>,
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
            pending_status: None,
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
        let mut status_bits = header.status_bits();

        let payload = match self.pending_type {
            None if is_last => payload,
            None => {
                self.pending_type = Some(header.r#type());
                self.pending_payload = payload;
                self.pending_status = Some(status_bits);
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
                status_bits = self.pending_status.take().unwrap_or(status_bits);
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
                if let Some(sspi) = decode_sspi_login(&payload)? {
                    TdsFrontendMessage::Sspi(sspi)
                } else {
                    let mut payload = payload;
                    let message = LoginMessage::decode(&mut payload)?;
                    TdsFrontendMessage::Login(message)
                }
            }
            PacketType::SQLBatch => {
                let mut payload = payload;
                let batch = decode_sql_batch(&mut payload, status_bits)?;
                TdsFrontendMessage::SqlBatch(batch)
            }
            PacketType::Rpc => {
                let message = decode_rpc(payload, status_bits)?;
                TdsFrontendMessage::Rpc(message)
            }
            PacketType::BulkLoad => TdsFrontendMessage::BulkLoad(payload),
            PacketType::AttentionSignal => TdsFrontendMessage::Attention,
            PacketType::Sspi => {
                let token = decode_sspi_payload(payload)?;
                TdsFrontendMessage::Sspi(token)
            }
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

fn decode_sspi_login(payload: &BytesMut) -> Result<Option<TokenSspi>> {
    if payload.len() < 3 || payload[0] != TokenType::Sspi as u8 {
        return Ok(None);
    }

    let len = u16::from_le_bytes([payload[1], payload[2]]) as usize;
    if payload.len() != 3 + len {
        return Ok(None);
    }

    let token = TokenSspi::from_bytes(payload[3..].to_vec());
    Ok(Some(token))
}

fn decode_sspi_payload(mut payload: BytesMut) -> Result<TokenSspi> {
    if payload.is_empty() {
        return Err(Error::Protocol("sspi: empty payload".into()));
    }

    if payload[0] == TokenType::Sspi as u8 {
        payload.advance(1);
        if payload.len() < 2 {
            return Err(Error::Protocol("sspi: missing length".into()));
        }
        let len = payload.get_u16_le() as usize;
        if payload.len() < len {
            return Err(Error::Protocol("sspi: truncated payload".into()));
        }
        let bytes = payload.split_to(len).to_vec();
        Ok(TokenSspi::from_bytes(bytes))
    } else {
        Ok(TokenSspi::from_bytes(payload.to_vec()))
    }
}

fn decode_sql_batch(payload: &mut BytesMut, status_bits: u8) -> Result<SqlBatchMessage> {
    let mut cursor = Cursor::new(payload);
    if cursor.get_ref().len() < 4 {
        return Err(Error::Protocol("sql batch: missing headers length".into()));
    }
    let headers_len = cursor.read_u32::<LittleEndian>()? as usize;
    if headers_len < 4 || headers_len > cursor.get_ref().len() {
        return Err(Error::Protocol("sql batch: invalid headers length".into()));
    }
    let headers = decode_all_headers(&cursor.get_ref()[..headers_len])?;
    cursor.set_position(headers_len as u64);

    let remaining = &cursor.get_ref()[headers_len..];
    if remaining.len() % 2 != 0 {
        return Err(Error::Protocol("sql batch: invalid utf16 length".into()));
    }
    let mut units = Vec::with_capacity(remaining.len() / 2);
    for chunk in remaining.chunks_exact(2) {
        units.push(u16::from_le_bytes([chunk[0], chunk[1]]));
    }

    let batch = String::from_utf16(&units).map_err(|_| Error::Utf16)?;
    Ok(SqlBatchMessage {
        batch,
        headers,
        request_flags: RequestFlags::from_status_bits(status_bits),
    })
}

fn decode_rpc(mut payload: BytesMut, status_bits: u8) -> Result<RpcMessage> {
    let mut cursor = Cursor::new(&payload);
    if cursor.get_ref().len() < 4 {
        return Err(Error::Protocol("rpc: missing headers length".into()));
    }
    let headers_len = cursor.read_u32::<LittleEndian>()? as usize;
    if headers_len < 4 || headers_len > cursor.get_ref().len() {
        return Err(Error::Protocol("rpc: invalid headers length".into()));
    }
    let headers = decode_all_headers(&cursor.get_ref()[..headers_len])?;
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
        headers,
        request_flags: RequestFlags::from_status_bits(status_bits),
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

fn decode_all_headers(bytes: &[u8]) -> Result<AllHeaders> {
    if bytes.len() < 4 {
        return Err(Error::Protocol("all headers: missing length".into()));
    }

    let mut cursor = Cursor::new(bytes);
    let total_len = cursor.read_u32::<LittleEndian>()? as usize;
    if total_len < 4 || total_len > bytes.len() {
        return Err(Error::Protocol("all headers: invalid length".into()));
    }

    let mut headers = AllHeaders::default();
    let mut consumed = 4usize;

    while consumed < total_len {
        if total_len - consumed < 6 {
            return Err(Error::Protocol("all headers: truncated header".into()));
        }

        let header_len = cursor.read_u32::<LittleEndian>()? as usize;
        let header_type = cursor.read_u16::<LittleEndian>()?;
        if header_len < 6 || consumed + header_len > total_len {
            return Err(Error::Protocol("all headers: invalid header length".into()));
        }

        let data_len = header_len - 6;
        let mut data = vec![0u8; data_len];
        cursor.read_exact(&mut data)?;
        consumed += header_len;

        match header_type {
            1 => {
                headers.query_descriptor = Some(data);
            }
            2 => {
                if data_len != 12 {
                    return Err(Error::Protocol(
                        "all headers: invalid transaction descriptor length".into(),
                    ));
                }
                let mut descriptor = [0u8; 8];
                descriptor.copy_from_slice(&data[..8]);
                let outstanding_requests = u32::from_le_bytes([
                    data[8], data[9], data[10], data[11],
                ]);
                headers.transaction_descriptor = Some(TransactionDescriptorHeader {
                    descriptor,
                    outstanding_requests,
                });
            }
            3 => {
                if data_len != 20 {
                    return Err(Error::Protocol(
                        "all headers: invalid trace activity length".into(),
                    ));
                }
                let mut activity_id = [0u8; 16];
                activity_id.copy_from_slice(&data[..16]);
                let sequence_number =
                    u32::from_le_bytes([data[16], data[17], data[18], data[19]]);
                headers.trace_activity = Some(TraceActivityHeader {
                    activity_id,
                    sequence_number,
                });
            }
            _ => {
                headers.unknown.push(UnknownHeader {
                    header_type,
                    data,
                });
            }
        }
    }

    Ok(headers)
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
