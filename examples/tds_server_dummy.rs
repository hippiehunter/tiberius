//! Dummy TDS server for protocol testing.
//!
//! Run with:
//!   cargo run --example tds_server_dummy --features server-smol

#[cfg(not(feature = "server-smol"))]
fn main() {
    eprintln!("Enable the server-smol feature to run this example.");
}

#[cfg(feature = "server-smol")]
mod server {
    use futures_lite::future;
    use futures_util::sink::SinkExt;

    use tiberius::server::backend::smol_net::SmolNetBackend;
    use tiberius::server::backend::{NetBackend, NetListener};
    use tiberius::server::codec::{decode_rpc_params, DecodedRpcParam};
    use tiberius::server::{
        process_connection, AttentionHandler, AuthHandler, BulkLoadHandler, ErrorHandler,
        ResultSetWriter, RpcHandler, SqlBatchHandler, TdsBackendMessage, TdsClientInfo,
        TdsConnectionState, TdsServerHandlers,
    };
    use tiberius::{
        numeric::Numeric,
        time::DateTime,
        BaseMetaDataColumn, Collation, ColumnData, ColumnFlag, FixedLenType, LoginMessage,
        MetaDataColumn, PreloginMessage, RpcStatus, TokenDone, TokenEnvChange, TokenInfo,
        TokenLoginAck, TokenReturnValue, TypeInfo, Uuid, VarLenContext, VarLenType,
    };
    use tiberius::{EncryptionLevel, Result};

    #[cfg(feature = "server-rustls")]
    use async_rustls::rustls::{Certificate, PrivateKey, ServerConfig};
    #[cfg(feature = "server-rustls")]
    use std::fs::File;
    #[cfg(feature = "server-rustls")]
    use std::io::BufReader;
    #[cfg(feature = "server-rustls")]
    use std::sync::Arc;
    #[cfg(feature = "server-rustls")]
    use tiberius::server::RustlsAcceptor;

    fn log_event(event: &str) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default();
        eprintln!(
            "[tds-dummy {:>10}.{:03}] {event}",
            now.as_secs(),
            now.subsec_millis()
        );
    }

    fn meta_fixed(name: &str, ty: FixedLenType) -> MetaDataColumn<'static> {
        MetaDataColumn {
            base: BaseMetaDataColumn {
                flags: ColumnFlag::Nullable.into(),
                ty: TypeInfo::FixedLen(ty),
            },
            col_name: name.to_string().into(),
        }
    }

    fn meta_var(
        name: &str,
        ty: VarLenType,
        len: usize,
        collation: Option<Collation>,
    ) -> MetaDataColumn<'static> {
        MetaDataColumn {
            base: BaseMetaDataColumn {
                flags: ColumnFlag::Nullable.into(),
                ty: TypeInfo::VarLenSized(VarLenContext::new(ty, len, collation)),
            },
            col_name: name.to_string().into(),
        }
    }

    fn numeric_len(precision: u8) -> usize {
        match precision {
            1..=9 => 5,
            10..=19 => 9,
            20..=28 => 13,
            _ => 17,
        }
    }

    fn meta_numeric(name: &str, precision: u8, scale: u8) -> MetaDataColumn<'static> {
        MetaDataColumn {
            base: BaseMetaDataColumn {
                flags: ColumnFlag::Nullable.into(),
                ty: TypeInfo::VarLenSizedPrecision {
                    ty: VarLenType::Numericn,
                    size: numeric_len(precision),
                    precision,
                    scale,
                },
            },
            col_name: name.to_string().into(),
        }
    }

    fn param_value_to_string(value: &ColumnData<'_>) -> String {
        match value {
            ColumnData::U8(Some(v)) => v.to_string(),
            ColumnData::I16(Some(v)) => v.to_string(),
            ColumnData::I32(Some(v)) => v.to_string(),
            ColumnData::I64(Some(v)) => v.to_string(),
            ColumnData::F32(Some(v)) => v.to_string(),
            ColumnData::F64(Some(v)) => v.to_string(),
            ColumnData::Bit(Some(v)) => v.to_string(),
            ColumnData::String(Some(s)) => s.to_string(),
            ColumnData::Guid(Some(g)) => g.to_string(),
            ColumnData::Binary(Some(b)) => format!("{:?}", b),
            ColumnData::Numeric(Some(n)) => format!("{n}"),
            ColumnData::DateTime(Some(dt)) => format!("{dt:?}"),
            ColumnData::SmallDateTime(Some(dt)) => format!("{dt:?}"),
            ColumnData::U8(None)
            | ColumnData::I16(None)
            | ColumnData::I32(None)
            | ColumnData::I64(None)
            | ColumnData::F32(None)
            | ColumnData::F64(None)
            | ColumnData::Bit(None)
            | ColumnData::String(None)
            | ColumnData::Guid(None)
            | ColumnData::Binary(None)
            | ColumnData::Numeric(None)
            | ColumnData::DateTime(None)
            | ColumnData::SmallDateTime(None) => "<null>".to_string(),
            _ => format!("{value:?}"),
        }
    }

    fn rpc_output_value(param: &DecodedRpcParam) -> ColumnData<'static> {
        match &param.ty {
            TypeInfo::FixedLen(FixedLenType::Int4) => ColumnData::I32(Some(4242)),
            TypeInfo::FixedLen(FixedLenType::Int8) => ColumnData::I64(Some(4242)),
            TypeInfo::VarLenSized(cx) if cx.r#type() == VarLenType::Intn && cx.len() <= 4 => {
                ColumnData::I32(Some(4242))
            }
            TypeInfo::VarLenSized(cx) if cx.r#type() == VarLenType::Intn && cx.len() == 8 => {
                ColumnData::I64(Some(4242))
            }
            TypeInfo::VarLenSized(cx) if cx.r#type() == VarLenType::Bitn => {
                ColumnData::Bit(Some(true))
            }
            TypeInfo::VarLenSized(cx) if cx.r#type() == VarLenType::NVarchar => {
                ColumnData::String(Some("out".into()))
            }
            _ => param.value.clone(),
        }
    }

    struct DummyHandlers {
        auth: DummyAuth,
        sql: DummySqlBatch,
        rpc: DummyRpc,
        bulk: DummyBulk,
        attention: DummyAttention,
        error: DummyErrorHandler,
    }

    impl DummyHandlers {
        fn new(encryption: EncryptionLevel) -> Self {
            Self {
                auth: DummyAuth { encryption },
                sql: DummySqlBatch,
                rpc: DummyRpc,
                bulk: DummyBulk,
                attention: DummyAttention,
                error: DummyErrorHandler,
            }
        }
    }

    impl TdsServerHandlers for DummyHandlers {
        type Auth = DummyAuth;
        type SqlBatch = DummySqlBatch;
        type Rpc = DummyRpc;
        type Bulk = DummyBulk;
        type Attention = DummyAttention;
        type Error = DummyErrorHandler;

        fn auth_handler(&self) -> &Self::Auth {
            &self.auth
        }

        fn sql_batch_handler(&self) -> &Self::SqlBatch {
            &self.sql
        }

        fn rpc_handler(&self) -> &Self::Rpc {
            &self.rpc
        }

        fn bulk_load_handler(&self) -> &Self::Bulk {
            &self.bulk
        }

        fn attention_handler(&self) -> &Self::Attention {
            &self.attention
        }

        fn error_handler(&self) -> &Self::Error {
            &self.error
        }
    }

    struct DummyAuth {
        encryption: EncryptionLevel,
    }

    impl AuthHandler for DummyAuth {
        fn on_prelogin<'a, C>(
            &'a self,
            client: &'a mut C,
            message: PreloginMessage,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>
        where
            C: TdsClientInfo
                + futures_util::sink::Sink<TdsBackendMessage, Error = tiberius::error::Error>
                + Unpin
                + Send
                + 'a,
        {
            Box::pin(async move {
                log_event(&format!(
                    "prelogin from={} encryption={:?} mars={} fed_auth_required={} instance={}",
                    client.socket_addr(),
                    message.encryption,
                    message.mars,
                    message.fed_auth_required,
                    message.instance_name.as_deref().unwrap_or("<none>")
                ));
                let mut reply = PreloginMessage::new();
                reply.encryption = self.encryption;
                client.set_encryption(reply.encryption);
                // SQL Server does not echo the instance name in prelogin replies.
                reply.instance_name = None;
                // Echo the client-provided version fields to satisfy strict clients.
                reply.version = message.version;
                reply.sub_build = message.sub_build;
                reply.thread_id = 0;

                client.send(TdsBackendMessage::Prelogin(reply)).await?;
                client.set_state(TdsConnectionState::AwaitingLogin);
                Ok(())
            })
        }

        fn on_login<'a, C>(
            &'a self,
            client: &'a mut C,
            message: LoginMessage<'static>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>
        where
            C: TdsClientInfo
                + futures_util::sink::Sink<TdsBackendMessage, Error = tiberius::error::Error>
                + Unpin
                + Send
                + 'a,
        {
            Box::pin(async move {
                let db_name = message.db_name_ref();
                let db_name = if db_name.is_empty() { "master" } else { db_name };

                log_event(&format!(
                    "login from={} user={} app={} db={} tds_version={:?} packet_size={}",
                    client.socket_addr(),
                    message.user_name_ref(),
                    message.app_name_ref(),
                    db_name,
                    message.tds_version(),
                    message.packet_size()
                ));

                client.set_packet_size(message.packet_size());
                let ack = TokenLoginAck::new(1, message.tds_version(), "tiberius", 0);
                let env_db = TokenEnvChange::Database(db_name.to_string(), String::new());
                let env_packet =
                    TokenEnvChange::PacketSize(client.packet_size(), client.packet_size());
                let env_collation = TokenEnvChange::SqlCollation {
                    old: None,
                    new: Some(Collation::new(13632521, 52)),
                };
                let done = TokenDone::default();

                client
                    .send(TdsBackendMessage::Tokens(vec![
                        tiberius::server::BackendToken::LoginAck(ack),
                        tiberius::server::BackendToken::EnvChange(env_db),
                        tiberius::server::BackendToken::EnvChange(env_packet),
                        tiberius::server::BackendToken::EnvChange(env_collation),
                        tiberius::server::BackendToken::Done(done),
                    ]))
                    .await?;

                client.set_state(TdsConnectionState::ReadyForQuery);
                Ok(())
            })
        }
    }

    struct DummySqlBatch;

    impl SqlBatchHandler for DummySqlBatch {
        fn on_sql_batch<'a, C>(
            &'a self,
            client: &'a mut C,
            batch: String,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>
        where
            C: TdsClientInfo
                + futures_util::sink::Sink<TdsBackendMessage, Error = tiberius::error::Error>
                + Unpin
                + Send
                + 'a,
        {
            Box::pin(async move {
                log_event(&format!(
                    "sql_batch from={} batch={:?}",
                    client.socket_addr(),
                    batch
                ));
                let lower = batch.to_ascii_lowercase();
                let collation = Some(Collation::new(13632521, 52));

                if lower.contains("tds_info") {
                    log_event("sql_batch: tds_info");
                    let info = TokenInfo::new(
                        5701,
                        0,
                        0,
                        "dummy info token",
                        "tiberius",
                        "tds_dummy",
                        1,
                    );
                    client
                        .send(TdsBackendMessage::Token(tiberius::server::BackendToken::Info(
                            info,
                        )))
                        .await?;
                }

                if lower.contains("tds_multi") {
                    log_event("sql_batch: tds_multi");
                    let columns = vec![
                        meta_fixed("id", FixedLenType::Int4),
                        meta_var("label", VarLenType::NVarchar, 200, collation),
                    ];
                    let mut writer = ResultSetWriter::start(client, columns).await?;
                    writer
                        .send_batch_rows(2, |row, col| match (row, col) {
                            (0, 0) => ColumnData::I32(Some(1)),
                            (0, 1) => ColumnData::String(Some("alpha".into())),
                            (1, 0) => ColumnData::I32(Some(2)),
                            (1, 1) => ColumnData::String(Some("beta".into())),
                            _ => ColumnData::I32(None),
                        })
                        .await?;
                    writer.finish_more(2).await?;

                    let columns = vec![
                        meta_fixed("code", FixedLenType::Int4),
                        meta_var("note", VarLenType::NVarchar, 200, collation),
                    ];
                    let mut writer = ResultSetWriter::start(client, columns).await?;
                    writer
                        .send_row_iter([ColumnData::I32(Some(100)), ColumnData::String(Some(
                            "gamma".into(),
                        ))])
                        .await?;
                    writer.finish(1).await?;
                    return Ok(());
                }

                if lower.contains("tds_types") {
                    log_event("sql_batch: tds_types");
                    let num0 = Numeric::new_with_scale(12345, 2);
                    let num1 = Numeric::new_with_scale(9999, 2);
                    let guid0 = Uuid::from_u128(1);
                    let guid1 = Uuid::from_u128(2);
                    let dt0 = DateTime::new(0, 0);
                    let dt1 = DateTime::new(1, 300);

                    let columns = vec![
                        meta_fixed("int_col", FixedLenType::Int4),
                        meta_fixed("bigint_col", FixedLenType::Int8),
                        meta_fixed("float_col", FixedLenType::Float8),
                        meta_fixed("bit_col", FixedLenType::Bit),
                        meta_var("nvarchar_col", VarLenType::NVarchar, 200, collation),
                        meta_var("varbinary_col", VarLenType::BigVarBin, 32, None),
                        meta_var("guid_col", VarLenType::Guid, 16, None),
                        meta_numeric("numeric_col", num0.precision(), num0.scale()),
                        meta_var("datetime_col", VarLenType::Datetimen, 8, None),
                    ];

                    let mut writer = ResultSetWriter::start(client, columns).await?;
                    writer
                        .send_batch_rows(2, |row, col| match (row, col) {
                            (0, 0) => ColumnData::I32(Some(42)),
                            (0, 1) => ColumnData::I64(Some(9001)),
                            (0, 2) => ColumnData::F64(Some(3.14159)),
                            (0, 3) => ColumnData::Bit(Some(true)),
                            (0, 4) => ColumnData::String(Some("hello".into())),
                            (0, 5) => ColumnData::Binary(Some(vec![1, 2, 3].into())),
                            (0, 6) => ColumnData::Guid(Some(guid0)),
                            (0, 7) => ColumnData::Numeric(Some(num0)),
                            (0, 8) => ColumnData::DateTime(Some(dt0)),
                            (1, 0) => ColumnData::I32(Some(7)),
                            (1, 1) => ColumnData::I64(Some(123456789)),
                            (1, 2) => ColumnData::F64(Some(2.71828)),
                            (1, 3) => ColumnData::Bit(Some(false)),
                            (1, 4) => ColumnData::String(Some("world".into())),
                            (1, 5) => ColumnData::Binary(Some(vec![4, 5, 6, 7].into())),
                            (1, 6) => ColumnData::Guid(Some(guid1)),
                            (1, 7) => ColumnData::Numeric(Some(num1)),
                            (1, 8) => ColumnData::DateTime(Some(dt1)),
                            _ => ColumnData::I32(None),
                        })
                        .await?;
                    writer.finish(2).await?;
                    return Ok(());
                }

                if lower.contains("tds_nulls") {
                    log_event("sql_batch: tds_nulls");
                    let num = Numeric::new_with_scale(0, 2);
                    let columns = vec![
                        meta_var("int_null", VarLenType::Intn, 4, None),
                        meta_var("bit_null", VarLenType::Bitn, 1, None),
                        meta_var("float_null", VarLenType::Floatn, 8, None),
                        meta_var("nvarchar_null", VarLenType::NVarchar, 200, collation),
                        meta_var("binary_null", VarLenType::BigVarBin, 32, None),
                        meta_numeric("numeric_null", num.precision(), num.scale()),
                    ];
                    let mut writer = ResultSetWriter::start(client, columns).await?;
                    writer
                        .send_row_iter([
                            ColumnData::I32(None),
                            ColumnData::Bit(None),
                            ColumnData::F64(None),
                            ColumnData::String(None),
                            ColumnData::Binary(None),
                            ColumnData::Numeric(None),
                        ])
                        .await?;
                    writer.finish(1).await?;
                    return Ok(());
                }

                if lower.contains("tds_rpc") {
                    log_event("sql_batch: tds_rpc");
                    let columns = vec![meta_fixed("sql_value", FixedLenType::Int4)];
                    let mut writer = ResultSetWriter::start(client, columns).await?;
                    writer.send_row_iter([ColumnData::I32(Some(99))]).await?;
                    writer.finish(1).await?;
                    return Ok(());
                }

                if !lower.contains("select") {
                    log_event("sql_batch: non-select done");
                    client
                        .send(TdsBackendMessage::Token(tiberius::server::BackendToken::Done(
                            TokenDone::default(),
                        )))
                        .await?;
                    return Ok(());
                }

                log_event("sql_batch: default select");
                let columns = vec![meta_fixed("value", FixedLenType::Int4)];
                let mut writer = ResultSetWriter::start(client, columns).await?;
                writer.send_row_iter([ColumnData::I32(Some(1))]).await?;
                writer.finish(1).await?;
                Ok(())
            })
        }
    }

    struct DummyRpc;

    impl RpcHandler for DummyRpc {
        fn on_rpc<'a, C>(
            &'a self,
            client: &'a mut C,
            message: tiberius::server::RpcMessage,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>
        where
            C: TdsClientInfo
                + futures_util::sink::Sink<TdsBackendMessage, Error = tiberius::error::Error>
                + Unpin
                + Send
                + 'a,
        {
            Box::pin(async move {
                log_event(&format!(
                    "rpc from={} proc_id={:?} proc_name={:?} flags={:?} params_len={}",
                    client.socket_addr(),
                    message.proc_id,
                    message.proc_name.as_deref().unwrap_or("<none>"),
                    message.flags,
                    message.params.len()
                ));

                let params = decode_rpc_params(message.params).await?;
                if !params.is_empty() {
                    log_event(&format!("rpc params decoded={}", params.len()));
                }
                let proc_name = message.proc_name.as_deref().unwrap_or("");
                let output_only = proc_name.eq_ignore_ascii_case("tds_rpc_out");
                let output_first = proc_name.eq_ignore_ascii_case("tds_rpc_out_first");

                let info = TokenInfo::new(
                    8127,
                    0,
                    0,
                    "dummy rpc info",
                    "tiberius",
                    "tds_rpc",
                    1,
                );
                client
                    .send(TdsBackendMessage::Token(tiberius::server::BackendToken::Info(
                        info,
                    )))
                    .await?;

                let mut pending_return_tokens = {
                    let mut tokens = Vec::new();
                    for (idx, param) in params.iter().enumerate() {
                        if !param.flags.contains(RpcStatus::ByRefValue) {
                            continue;
                        }

                        let ordinal = (idx + 1) as u16;
                        let name = param.name.clone();
                        let meta = BaseMetaDataColumn {
                            flags: ColumnFlag::Nullable.into(),
                            ty: param.ty.clone(),
                        };
                        let value = rpc_output_value(param);

                        tokens.push(tiberius::server::BackendToken::ReturnValue(
                            TokenReturnValue {
                                param_ordinal: ordinal,
                                param_name: name,
                                udf: false,
                                meta,
                                value,
                            },
                        ));
                    }

                    tokens.push(tiberius::server::BackendToken::ReturnStatus(0));
                    Some(tokens)
                };

                if output_first {
                    log_event("rpc output-first mode enabled");
                    if let Some(tokens) = pending_return_tokens.take() {
                        client.send(TdsBackendMessage::Tokens(tokens)).await?;
                    }
                }

                if !output_only && !params.is_empty() {
                    let collation = Some(Collation::new(13632521, 52));
                    let columns = vec![
                        meta_fixed("param_ordinal", FixedLenType::Int4),
                        meta_var("param_name", VarLenType::NVarchar, 200, collation),
                        meta_fixed("param_flags", FixedLenType::Int4),
                        meta_var("param_type", VarLenType::NVarchar, 512, collation),
                        meta_var("param_value", VarLenType::NVarchar, 1024, collation),
                    ];
                    let mut writer = ResultSetWriter::start(client, columns).await?;
                    for (idx, param) in params.iter().enumerate() {
                        let ordinal = (idx + 1) as i32;
                        let name = if param.name.is_empty() {
                            format!("@P{ordinal}")
                        } else {
                            param.name.clone()
                        };
                        let flags = param.flags.bits() as i32;
                        let ty = format!("{:?}", param.ty);
                        let value = param_value_to_string(&param.value);

                        writer
                            .send_row_iter([
                                ColumnData::I32(Some(ordinal)),
                                ColumnData::String(Some(name.into())),
                                ColumnData::I32(Some(flags)),
                                ColumnData::String(Some(ty.into())),
                                ColumnData::String(Some(value.into())),
                            ])
                            .await?;
                    }
                    writer.finish_more_in_proc(params.len() as u64).await?;
                }

                if !output_only {
                    let collation = Some(Collation::new(13632521, 52));
                    let columns = vec![
                        meta_fixed("rpc_value", FixedLenType::Int4),
                        meta_var("rpc_note", VarLenType::NVarchar, 200, collation),
                    ];
                    let mut writer = ResultSetWriter::start(client, columns).await?;
                    writer
                        .send_row_iter([
                            ColumnData::I32(Some(7)),
                            ColumnData::String(Some("rpc".into())),
                        ])
                        .await?;
                    writer.finish_more_in_proc(1).await?;
                }

                if let Some(tokens) = pending_return_tokens.take() {
                    client.send(TdsBackendMessage::Tokens(tokens)).await?;
                }

                client
                    .send(TdsBackendMessage::Token(tiberius::server::BackendToken::DoneProc(
                        TokenDone::with_rows(1),
                    )))
                    .await
            })
        }
    }

    struct DummyBulk;

    impl BulkLoadHandler for DummyBulk {
        fn on_bulk_load<'a, C>(
            &'a self,
            client: &'a mut C,
            _payload: bytes::BytesMut,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>
        where
            C: TdsClientInfo
                + futures_util::sink::Sink<TdsBackendMessage, Error = tiberius::error::Error>
                + Unpin
                + Send
                + 'a,
        {
            Box::pin(async move {
                client
                    .send(TdsBackendMessage::Token(tiberius::server::BackendToken::Done(
                        TokenDone::default(),
                    )))
                    .await
            })
        }
    }

    struct DummyAttention;

    impl AttentionHandler for DummyAttention {
        fn on_attention<'a, C>(
            &'a self,
            client: &'a mut C,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>
        where
            C: TdsClientInfo
                + futures_util::sink::Sink<TdsBackendMessage, Error = tiberius::error::Error>
                + Unpin
                + Send
                + 'a,
        {
            Box::pin(async move {
                client.set_state(TdsConnectionState::ReadyForQuery);
                Ok(())
            })
        }
    }

    struct DummyErrorHandler;

    impl ErrorHandler for DummyErrorHandler {
        fn on_error(&self, _client: &dyn TdsClientInfo, error: &mut tiberius::error::Error) {
            eprintln!("tds dummy server error: {error}");
        }
    }

    #[cfg(feature = "server-rustls")]
    fn resolve_encryption(tls_acceptor: &Option<RustlsAcceptor>) -> EncryptionLevel {
        let requested = std::env::var("TDS_DUMMY_ENCRYPTION")
            .ok()
            .and_then(|value| parse_encryption(&value));

        match (tls_acceptor.is_some(), requested) {
            (false, Some(level)) => {
                log_event(&format!(
                    "TLS disabled; ignoring requested encryption={level:?}"
                ));
                EncryptionLevel::NotSupported
            }
            (false, None) => EncryptionLevel::NotSupported,
            (true, Some(level)) => level,
            (true, None) => EncryptionLevel::On,
        }
    }

    #[cfg(feature = "server-rustls")]
    fn parse_encryption(value: &str) -> Option<EncryptionLevel> {
        match value.trim().to_ascii_lowercase().as_str() {
            "off" => Some(EncryptionLevel::Off),
            "on" => Some(EncryptionLevel::On),
            "required" | "require" => Some(EncryptionLevel::Required),
            "none" | "not_supported" | "disabled" => Some(EncryptionLevel::NotSupported),
            _ => None,
        }
    }

    #[cfg(feature = "server-rustls")]
    fn load_tls_acceptor() -> Option<RustlsAcceptor> {
        let cert_path = std::env::var("TDS_DUMMY_TLS_CERT").ok()?;
        let key_path = std::env::var("TDS_DUMMY_TLS_KEY").ok()?;

        let certs = load_certs(&cert_path)?;
        let key = load_private_key(&key_path)?;

        let config = ServerConfig::builder()
            .with_safe_defaults()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .map_err(|err| {
                log_event(&format!("TLS config error: {err}"));
                err
            })
            .ok()?;

        Some(RustlsAcceptor::new(Arc::new(config)))
    }

    #[cfg(feature = "server-rustls")]
    fn load_certs(path: &str) -> Option<Vec<Certificate>> {
        let file = File::open(path).ok()?;
        let mut reader = BufReader::new(file);
        let certs = rustls_pemfile::certs(&mut reader).ok()?;
        if certs.is_empty() {
            log_event(&format!("TLS cert file empty: {path}"));
            return None;
        }
        Some(certs.into_iter().map(Certificate).collect())
    }

    #[cfg(feature = "server-rustls")]
    fn load_private_key(path: &str) -> Option<PrivateKey> {
        let file = File::open(path).ok()?;
        let mut reader = BufReader::new(file);
        let mut keys = rustls_pemfile::pkcs8_private_keys(&mut reader).ok()?;
        if let Some(key) = keys.pop() {
            return Some(PrivateKey(key));
        }

        let file = File::open(path).ok()?;
        let mut reader = BufReader::new(file);
        let mut keys = rustls_pemfile::rsa_private_keys(&mut reader).ok()?;
        if let Some(key) = keys.pop() {
            return Some(PrivateKey(key));
        }

        log_event(&format!("TLS key file missing usable keys: {path}"));
        None
    }

    pub fn run() {
        future::block_on(async {
            let listener = SmolNetBackend::bind("0.0.0.0:14333")
                .await
                .expect("bind failed");
            log_event("Dummy TDS server listening on 0.0.0.0:14333");

            #[cfg(feature = "server-rustls")]
            let tls_acceptor = load_tls_acceptor();
            #[cfg(feature = "server-rustls")]
            let encryption = resolve_encryption(&tls_acceptor);

            #[cfg(not(feature = "server-rustls"))]
            let encryption = EncryptionLevel::NotSupported;

            log_event(&format!("encryption policy: {encryption:?}"));
            #[cfg(feature = "server-rustls")]
            log_event(&format!(
                "TLS acceptor: {}",
                if tls_acceptor.is_some() { "enabled" } else { "disabled" }
            ));

            let handlers = DummyHandlers::new(encryption);

            loop {
                let (stream, _addr) = listener.accept().await.expect("accept failed");
                log_event(&format!("accepted connection from {}", _addr));
                #[cfg(feature = "server-rustls")]
                {
                    let tls = tls_acceptor.clone();
                    if let Err(err) = process_connection(stream, tls, &handlers).await {
                        eprintln!("connection error: {err}");
                    }
                }

                #[cfg(not(feature = "server-rustls"))]
                {
                    if let Err(err) = process_connection(
                        stream,
                        Option::<tiberius::server::NoTls>::None,
                        &handlers,
                    )
                    .await
                    {
                        eprintln!("connection error: {err}");
                    }
                }
            }
        });
    }
}

#[cfg(feature = "server-smol")]
fn main() {
    server::run();
}
