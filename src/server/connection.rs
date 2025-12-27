//! TDS connection abstraction.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;
use std::task::{Context, Poll};

use bytes::{BufMut, BytesMut};
use futures_util::sink::Sink;
use futures_util::stream::Stream;

use crate::server::backend::{NetStream, NetStreamExt};
use crate::server::codec::TdsCodec;
use crate::server::handler::TdsClientInfo;
use crate::server::messages::{BackendToken, TdsBackendMessage, TdsFrontendMessage};
use crate::server::state::TdsConnectionState;
use crate::tds::codec::{Encode, Packet, PacketHeader, PacketStatus, PacketType};
use std::sync::Arc;
use crate::tds::Context as TdsContext;
use crate::Error;
use crate::EncryptionLevel;

/// Buffer size for read/write operations.
const BUFFER_SIZE: usize = 8192;

/// A TDS connection over any NetStream backend.
pub struct TdsConnection<S: NetStream> {
    stream: S,
    codec: TdsCodec,
    metadata: HashMap<String, String>,
    state: TdsConnectionState,
    context: TdsContext,
    read_buf: BytesMut,
    write_buf: BytesMut,
    needs_flush: bool,
    is_secure: bool,
    encryption: EncryptionLevel,
    socket_addr: SocketAddr,
}

impl<S: NetStream> TdsConnection<S> {
    /// Create a new connection wrapping the given stream.
    pub fn new(stream: S) -> Self {
        let socket_addr = stream
            .peer_addr()
            .unwrap_or_else(|_| "0.0.0.0:0".parse().unwrap());

        Self {
            stream,
            codec: TdsCodec::new(),
            metadata: HashMap::new(),
            state: TdsConnectionState::AwaitingPrelogin,
            context: TdsContext::new(),
            read_buf: BytesMut::with_capacity(BUFFER_SIZE),
            write_buf: BytesMut::with_capacity(BUFFER_SIZE),
            needs_flush: false,
            is_secure: false,
            encryption: EncryptionLevel::NotSupported,
            socket_addr,
        }
    }

    /// Get a reference to the codec.
    pub fn codec(&self) -> &TdsCodec {
        &self.codec
    }

    /// Get a mutable reference to the codec.
    pub fn codec_mut(&mut self) -> &mut TdsCodec {
        &mut self.codec
    }

    /// Get the underlying stream.
    pub fn stream(&self) -> &S {
        &self.stream
    }

    /// Get a mutable reference to the underlying stream.
    pub fn stream_mut(&mut self) -> &mut S {
        &mut self.stream
    }

    /// Mark the connection as secure (TLS enabled).
    pub fn set_secure(&mut self, secure: bool) {
        self.is_secure = secure;
    }

    /// Get the negotiated encryption level.
    pub fn encryption(&self) -> EncryptionLevel {
        self.encryption
    }

    /// Set the negotiated encryption level.
    pub fn set_encryption(&mut self, encryption: EncryptionLevel) {
        self.encryption = encryption;
    }

    /// Write raw bytes to the connection.
    pub async fn write_raw(&mut self, data: &[u8]) -> io::Result<()> {
        let mut written = 0;
        while written < data.len() {
            let n = self.stream.write(&data[written..]).await?;
            if n == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "failed to write data",
                ));
            }
            written += n;
        }
        self.stream.flush().await
    }

    /// Try to read more data into the buffer.
    fn poll_read_buf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<usize>> {
        if self.read_buf.capacity() - self.read_buf.len() < 1024 {
            self.read_buf.reserve(BUFFER_SIZE);
        }

        let mut tmp = [0u8; BUFFER_SIZE];
        match Pin::new(&mut self.stream).poll_read(cx, &mut tmp) {
            Poll::Ready(Ok(0)) => Poll::Ready(Ok(0)),
            Poll::Ready(Ok(n)) => {
                self.read_buf.extend_from_slice(&tmp[..n]);
                Poll::Ready(Ok(n))
            }
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Pending => Poll::Pending,
        }
    }

    /// Try to flush the write buffer.
    fn poll_flush_buf(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        while !self.write_buf.is_empty() {
            match Pin::new(&mut self.stream).poll_write(cx, &self.write_buf) {
                Poll::Ready(Ok(0)) => {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::WriteZero,
                        "failed to write data",
                    )));
                }
                Poll::Ready(Ok(n)) => {
                    let _ = self.write_buf.split_to(n);
                }
                Poll::Ready(Err(e)) => return Poll::Ready(Err(e)),
                Poll::Pending => return Poll::Pending,
            }
        }

        if self.needs_flush {
            match Pin::new(&mut self.stream).poll_flush(cx) {
                Poll::Ready(Ok(())) => {
                    self.needs_flush = false;
                    Poll::Ready(Ok(()))
                }
                Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
                Poll::Pending => Poll::Pending,
            }
        } else {
            Poll::Ready(Ok(()))
        }
    }

    /// Decode a message from the read buffer.
    fn try_decode(&mut self) -> Result<Option<TdsFrontendMessage>, Error> {
        self.codec.decode(&mut self.read_buf, self.state)
    }

    /// Encode a message into the write buffer.
    fn do_encode(&mut self, msg: TdsBackendMessage) -> Result<(), Error> {
        match msg {
            TdsBackendMessage::Prelogin(message) => {
                let mut payload = BytesMut::new();
                message.encode(&mut payload)?;
                // FreeTDS expects prelogin replies in a TDS_REPLY packet (0x04).
                self.write_payload_as_packets(PacketType::TabularResult, payload)?;
                Ok(())
            }
            TdsBackendMessage::Token(token) => {
                self.encode_tokens(std::iter::once(token))?;
                Ok(())
            }
            TdsBackendMessage::Tokens(tokens) => {
                self.encode_tokens(tokens.into_iter())?;
                Ok(())
            }
            TdsBackendMessage::TokenBytes(payload) => {
                self.write_payload_as_packets(PacketType::TabularResult, payload)?;
                Ok(())
            }
            TdsBackendMessage::Packet(packet) => self.codec.encode(TdsBackendMessage::Packet(packet), &mut self.write_buf),
        }
    }

    fn encode_tokens<I>(&mut self, tokens: I) -> Result<(), Error>
    where
        I: IntoIterator<Item = BackendToken>,
    {
        let mut payload = BytesMut::new();
        for token in tokens {
            self.encode_token(token, &mut payload)?;
        }
        self.write_payload_as_packets(PacketType::TabularResult, payload)?;
        Ok(())
    }

    fn encode_token(&mut self, token: BackendToken, payload: &mut BytesMut) -> Result<(), Error> {
        match token {
            BackendToken::LoginAck(token) => token.encode(payload),
            BackendToken::EnvChange(token) => token.encode(payload),
            BackendToken::Info(token) => token.encode(payload),
            BackendToken::Error(token) => token.encode(payload),
            BackendToken::FeatureExtAck(token) => token.encode(payload),
            BackendToken::ColMetaData(token) => {
                self.context.set_last_meta(Arc::new(token.clone()));
                token.encode(payload)
            }
            BackendToken::Row(token) => {
                let meta = self
                    .context
                    .last_meta()
                    .ok_or_else(|| Error::Protocol("missing column metadata".into()))?;
                token.encode_with_columns(payload, &meta.columns)
            }
            BackendToken::Done(token) => token.encode(payload),
            BackendToken::DoneProc(token) => {
                token.encode_with_type(payload, crate::tds::codec::TokenType::DoneProc)
            }
            BackendToken::DoneInProc(token) => {
                token.encode_with_type(payload, crate::tds::codec::TokenType::DoneInProc)
            }
            BackendToken::ReturnStatus(status) => {
                payload.put_u8(crate::tds::codec::TokenType::ReturnStatus as u8);
                payload.put_u32_le(status);
                Ok(())
            }
            BackendToken::ReturnValue(token) => token.encode(payload),
            BackendToken::Sspi(token) => token.encode(payload),
        }
    }

    fn write_payload_as_packets(
        &mut self,
        ty: PacketType,
        mut payload: BytesMut,
    ) -> Result<(), Error> {
        let packet_size = (self.context.packet_size() as usize)
            .saturating_sub(crate::tds::codec::HEADER_BYTES);

        if packet_size == 0 {
            return Err(Error::Protocol("invalid packet size".into()));
        }

        while !payload.is_empty() {
            let writable = std::cmp::min(payload.len(), packet_size);
            let split_payload = payload.split_to(writable);
            let id = self.context.next_packet_id();
            let mut header = PacketHeader::new(0, id);
            header.set_type(ty);
            if payload.is_empty() {
                header.set_status(PacketStatus::EndOfMessage);
            } else {
                header.set_status(PacketStatus::NormalMessage);
            }

            let packet = Packet::new(header, split_payload);
            self.codec
                .encode(TdsBackendMessage::Packet(packet), &mut self.write_buf)?;
        }

        self.needs_flush = true;
        Ok(())
    }
}

impl<S: NetStream> TdsClientInfo for TdsConnection<S> {
    fn socket_addr(&self) -> SocketAddr {
        self.socket_addr
    }

    fn is_secure(&self) -> bool {
        self.is_secure
    }

    fn state(&self) -> TdsConnectionState {
        self.state
    }

    fn set_state(&mut self, state: TdsConnectionState) {
        self.state = state;
    }

    fn metadata(&self) -> &HashMap<String, String> {
        &self.metadata
    }

    fn metadata_mut(&mut self) -> &mut HashMap<String, String> {
        &mut self.metadata
    }

    fn next_packet_id(&mut self) -> u8 {
        self.context.next_packet_id()
    }

    fn packet_size(&self) -> u32 {
        self.context.packet_size()
    }

    fn set_packet_size(&mut self, size: u32) {
        self.context.set_packet_size(size);
    }

    fn transaction_descriptor(&self) -> [u8; 8] {
        self.context.transaction_descriptor()
    }

    fn set_transaction_descriptor(&mut self, desc: [u8; 8]) {
        self.context.set_transaction_descriptor(desc);
    }

    fn encryption(&self) -> EncryptionLevel {
        self.encryption
    }

    fn set_encryption(&mut self, encryption: EncryptionLevel) {
        self.encryption = encryption;
    }
}

impl<S: NetStream> Stream for TdsConnection<S> {
    type Item = Result<TdsFrontendMessage, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();

        match this.try_decode() {
            Ok(Some(msg)) => return Poll::Ready(Some(Ok(msg))),
            Ok(None) => {}
            Err(e) => return Poll::Ready(Some(Err(e))),
        }

        match this.poll_read_buf(cx) {
            Poll::Ready(Ok(0)) => Poll::Ready(None),
            Poll::Ready(Ok(_)) => match this.try_decode() {
                Ok(Some(msg)) => Poll::Ready(Some(Ok(msg))),
                Ok(None) => Poll::Pending,
                Err(e) => Poll::Ready(Some(Err(e))),
            },
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(e.into()))),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<S: NetStream> Sink<TdsBackendMessage> for TdsConnection<S> {
    type Error = Error;

    fn poll_ready(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn start_send(self: Pin<&mut Self>, item: TdsBackendMessage) -> Result<(), Self::Error> {
        let this = self.get_mut();
        this.do_encode(item)?;
        this.needs_flush = true;
        Ok(())
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.get_mut()
            .poll_flush_buf(cx)
            .map_err(Into::into)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        let this = self.get_mut();
        match this.poll_flush_buf(cx) {
            Poll::Ready(Ok(())) => Pin::new(&mut this.stream)
                .poll_close(cx)
                .map_err(Into::into),
            Poll::Ready(Err(e)) => Poll::Ready(Err(e.into())),
            Poll::Pending => Poll::Pending,
        }
    }
}
