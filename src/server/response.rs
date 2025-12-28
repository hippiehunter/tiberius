//! Helpers for streaming resultsets efficiently.

use futures_util::sink::SinkExt;

use crate::server::handler::TdsClientInfo;
use crate::server::messages::{BackendToken, TdsBackendMessage};
use crate::server::state::TdsConnectionState;
use crate::tds::codec::{
    BytesMutWithTypeInfo, ColumnData, DoneStatus, Encode, MetaDataColumn, TokenColMetaData,
    TokenDone, TokenRow, TokenType, HEADER_BYTES,
};
use crate::Result;
use bytes::{BufMut, BytesMut};

/// A lightweight resultset writer that streams tokens directly to the client.
///
/// This keeps row encoding incremental and avoids buffering full resultsets,
/// which aligns well with Arrow batch producers.
pub struct ResultSetWriter<'a, C> {
    client: &'a mut C,
    columns: Vec<MetaDataColumn<'static>>,
}

impl<'a, C> ResultSetWriter<'a, C>
where
    C: TdsClientInfo
        + futures_util::sink::Sink<TdsBackendMessage, Error = crate::Error>
        + Unpin
        + Send,
{
    /// Start a new resultset and send column metadata.
    pub async fn start(client: &'a mut C, columns: Vec<MetaDataColumn<'static>>) -> Result<Self> {
        let token = TokenColMetaData {
            columns: columns.clone(),
        };
        client
            .send(TdsBackendMessage::TokenPartial(BackendToken::ColMetaData(token)))
            .await?;

        Ok(Self { client, columns })
    }

    /// Send a single row.
    pub async fn send_row(&mut self, row: TokenRow<'static>) -> Result<()> {
        let _ = &self.columns;
        self.client
            .send(TdsBackendMessage::TokenPartial(BackendToken::Row(row)))
            .await
    }

    /// Send a single row using NBCROW (null bitmap compression).
    pub async fn send_row_nbc(&mut self, row: TokenRow<'static>) -> Result<()> {
        let _ = &self.columns;
        self.client
            .send(TdsBackendMessage::TokenPartial(BackendToken::NbcRow(row)))
            .await
    }

    /// Send a single row from an iterator of column data.
    pub async fn send_row_iter<I>(&mut self, values: I) -> Result<()>
    where
        I: IntoIterator<Item = ColumnData<'static>>,
    {
        let mut row = TokenRow::with_capacity(self.columns.len());
        for value in values {
            row.push(value);
        }
        self.send_row(row).await
    }

    /// Send a single row (NBCROW) from an iterator of column data.
    pub async fn send_row_iter_nbc<I>(&mut self, values: I) -> Result<()>
    where
        I: IntoIterator<Item = ColumnData<'static>>,
    {
        let mut row = TokenRow::with_capacity(self.columns.len());
        for value in values {
            row.push(value);
        }
        self.send_row_nbc(row).await
    }

    /// Poll for an attention/cancel signal while streaming results.
    pub async fn poll_attention(&mut self) -> Result<bool> {
        self.client.poll_attention().await
    }

    /// Send a row only if no attention/cancel has been observed.
    pub async fn send_row_iter_checked<I>(&mut self, values: I) -> Result<bool>
    where
        I: IntoIterator<Item = ColumnData<'static>>,
    {
        if self.poll_attention().await? {
            return Ok(false);
        }
        self.send_row_iter(values).await?;
        Ok(true)
    }

    /// Send a row (NBCROW) only if no attention/cancel has been observed.
    pub async fn send_row_iter_nbc_checked<I>(&mut self, values: I) -> Result<bool>
    where
        I: IntoIterator<Item = ColumnData<'static>>,
    {
        if self.poll_attention().await? {
            return Ok(false);
        }
        self.send_row_iter_nbc(values).await?;
        Ok(true)
    }

    /// Send a row (NBCROW) from borrowed values without allocating a TokenRow.
    pub async fn send_row_values_nbc<'b, I>(&mut self, values: I) -> Result<()>
    where
        I: IntoIterator<Item = ColumnData<'b>>,
    {
        let mut row = TokenRow::with_capacity(self.columns.len());
        for value in values {
            row.push(value);
        }

        let mut payload = BytesMut::new();
        row.encode_nbc_with_columns(&mut payload, &self.columns)?;
        self.client
            .send(TdsBackendMessage::TokenBytesPartial(payload))
            .await
    }

    /// Send a row (NBCROW) from borrowed values only if no attention/cancel has been observed.
    pub async fn send_row_values_nbc_checked<'b, I>(&mut self, values: I) -> Result<bool>
    where
        I: IntoIterator<Item = ColumnData<'b>>,
    {
        if self.poll_attention().await? {
            return Ok(false);
        }
        self.send_row_values_nbc(values).await?;
        Ok(true)
    }

    /// Send a row from borrowed values only if no attention/cancel has been observed.
    pub async fn send_row_values_checked<'b, I>(&mut self, values: I) -> Result<bool>
    where
        I: IntoIterator<Item = ColumnData<'b>>,
    {
        if self.poll_attention().await? {
            return Ok(false);
        }
        self.send_row_values(values).await?;
        Ok(true)
    }

    /// Send a row from borrowed values without allocating a TokenRow.
    ///
    /// This is a better fit for columnar sources like Arrow because values
    /// can borrow directly from column buffers and are encoded immediately.
    pub async fn send_row_values<'b, I>(&mut self, values: I) -> Result<()>
    where
        I: IntoIterator<Item = ColumnData<'b>>,
    {
        let mut row = TokenRow::with_capacity(self.columns.len());
        for value in values {
            row.push(value);
        }

        let mut payload = BytesMut::new();
        row.encode_with_columns(&mut payload, &self.columns)?;
        self.client
            .send(TdsBackendMessage::TokenBytesPartial(payload))
            .await
    }

    /// Send a row from borrowed values, flushing chunks as the buffer grows.
    ///
    /// This avoids per-row buffering for large values by streaming chunks to the wire.
    pub async fn send_row_values_streaming<'b, I>(&mut self, values: I) -> Result<()>
    where
        I: IntoIterator<Item = ColumnData<'b>>,
    {
        let max_payload = (self.client.packet_size() as usize).saturating_sub(HEADER_BYTES);
        let chunk_size = std::cmp::max(256, max_payload);
        self.send_row_values_chunked(values, chunk_size).await
    }

    /// Send a row from borrowed values with a custom chunk size.
    pub async fn send_row_values_chunked<'b, I>(
        &mut self,
        values: I,
        chunk_size: usize,
    ) -> Result<()>
    where
        I: IntoIterator<Item = ColumnData<'b>>,
    {
        let chunk_size = std::cmp::max(1, chunk_size);
        let mut iter = values.into_iter();
        let mut payload = BytesMut::new();
        payload.put_u8(TokenType::Row as u8);

        for column in &self.columns {
            let value = iter.next().ok_or_else(|| {
                crate::Error::BulkInput(
                    format!(
                        "Expecting {} columns but fewer values were given",
                        self.columns.len()
                    )
                    .into(),
                )
            })?;
            let mut dst_ti = BytesMutWithTypeInfo::new(&mut payload).with_type_info(&column.base.ty);
            value.encode(&mut dst_ti)?;
            while payload.len() >= chunk_size {
                let chunk = payload.split_to(chunk_size);
                if !chunk.is_empty() {
                    self.client
                        .send(TdsBackendMessage::TokenBytesPartial(chunk))
                        .await?;
                }
            }
        }

        if iter.next().is_some() {
            return Err(crate::Error::BulkInput(
                format!(
                    "Expecting {} columns but more values were given",
                    self.columns.len()
                )
                .into(),
            ));
        }

        if !payload.is_empty() {
            self.client
                .send(TdsBackendMessage::TokenBytesPartial(payload))
                .await?;
        }

        Ok(())
    }

    /// Send a batch of rows using a columnar accessor.
    ///
    /// The accessor should provide a value for each (row, col) pair.
    pub async fn send_batch_rows<'b, F>(
        &mut self,
        rows: usize,
        mut value_at: F,
    ) -> Result<()>
    where
        F: FnMut(usize, usize) -> ColumnData<'b>,
    {
        let mut payload = BytesMut::new();
        for row_idx in 0..rows {
            let mut row = TokenRow::with_capacity(self.columns.len());
            for col_idx in 0..self.columns.len() {
                row.push(value_at(row_idx, col_idx));
            }
            row.encode_with_columns(&mut payload, &self.columns)?;
        }

        self.client
            .send(TdsBackendMessage::TokenBytesPartial(payload))
            .await
    }

    /// Send a batch of rows, stopping early if attention/cancel is observed.
    ///
    /// Returns the number of rows sent before attention was seen.
    pub async fn send_batch_rows_checked<'b, F>(
        &mut self,
        rows: usize,
        mut value_at: F,
    ) -> Result<usize>
    where
        F: FnMut(usize, usize) -> ColumnData<'b>,
    {
        let mut payload = BytesMut::new();
        let mut sent = 0usize;

        for row_idx in 0..rows {
            if self.poll_attention().await? {
                break;
            }
            let mut row = TokenRow::with_capacity(self.columns.len());
            for col_idx in 0..self.columns.len() {
                row.push(value_at(row_idx, col_idx));
            }
            row.encode_with_columns(&mut payload, &self.columns)?;
            sent += 1;
        }

        if sent > 0 {
            self.client
                .send(TdsBackendMessage::TokenBytesPartial(payload))
                .await?;
        }

        Ok(sent)
    }

    /// Send a batch of rows using NBCROW encoding.
    pub async fn send_batch_rows_nbc<'b, F>(
        &mut self,
        rows: usize,
        mut value_at: F,
    ) -> Result<()>
    where
        F: FnMut(usize, usize) -> ColumnData<'b>,
    {
        let mut payload = BytesMut::new();
        for row_idx in 0..rows {
            let mut row = TokenRow::with_capacity(self.columns.len());
            for col_idx in 0..self.columns.len() {
                row.push(value_at(row_idx, col_idx));
            }
            row.encode_nbc_with_columns(&mut payload, &self.columns)?;
        }

        self.client
            .send(TdsBackendMessage::TokenBytesPartial(payload))
            .await
    }

    /// Send a batch of rows using NBCROW, stopping early if attention/cancel is observed.
    ///
    /// Returns the number of rows sent before attention was seen.
    pub async fn send_batch_rows_nbc_checked<'b, F>(
        &mut self,
        rows: usize,
        mut value_at: F,
    ) -> Result<usize>
    where
        F: FnMut(usize, usize) -> ColumnData<'b>,
    {
        let mut payload = BytesMut::new();
        let mut sent = 0usize;

        for row_idx in 0..rows {
            if self.poll_attention().await? {
                break;
            }
            let mut row = TokenRow::with_capacity(self.columns.len());
            for col_idx in 0..self.columns.len() {
                row.push(value_at(row_idx, col_idx));
            }
            row.encode_nbc_with_columns(&mut payload, &self.columns)?;
            sent += 1;
        }

        if sent > 0 {
            self.client
                .send(TdsBackendMessage::TokenBytesPartial(payload))
                .await?;
        }

        Ok(sent)
    }

    /// Finish the resultset with a DONE token.
    pub async fn finish(self, rows: u64) -> Result<()> {
        let done = TokenDone::with_rows(rows);
        self.client
            .send(TdsBackendMessage::Token(BackendToken::Done(done)))
            .await
    }

    /// Finish the resultset with a custom DONE token.
    pub async fn finish_with_done(self, done: TokenDone) -> Result<()> {
        self.client
            .send(TdsBackendMessage::Token(BackendToken::Done(done)))
            .await
    }

    /// Finish the resultset indicating more results will follow.
    pub async fn finish_more(self, rows: u64) -> Result<()> {
        self.finish_with_done(TokenDone::with_more_rows(rows)).await
    }

    /// Finish the resultset with a DONEINPROC token (DONE_MORE set for a following DONEPROC).
    pub async fn finish_in_proc(self, rows: u64) -> Result<()> {
        let done = TokenDone::with_more_rows(rows);
        self.client
            .send(TdsBackendMessage::Token(BackendToken::DoneInProc(done)))
            .await
    }

    /// Finish the resultset with a DONEINPROC token indicating more results will follow.
    pub async fn finish_more_in_proc(self, rows: u64) -> Result<()> {
        let done = TokenDone::with_more_rows(rows);
        self.client
            .send(TdsBackendMessage::Token(BackendToken::DoneInProc(done)))
            .await
    }

    /// Finish the resultset with a DONE token indicating attention/cancel.
    pub async fn finish_attention(self, rows: u64) -> Result<()> {
        let done = TokenDone::with_status(DoneStatus::Attention | DoneStatus::Count, rows);
        self.finish_with_done(done).await
    }

    /// Finish the resultset with DONEATTENTION and reset attention state.
    pub async fn finish_attention_and_ready(self, rows: u64) -> Result<()> {
        let done = TokenDone::with_status(DoneStatus::Attention | DoneStatus::Count, rows);
        self.client
            .send(TdsBackendMessage::Token(BackendToken::Done(done)))
            .await?;
        self.client.clear_attention();
        self.client.set_state(TdsConnectionState::ReadyForQuery);
        Ok(())
    }

    /// Finish the resultset, sending DONEATTENTION if attention/cancel was observed.
    ///
    /// Returns true if attention was handled.
    pub async fn finish_or_attention(mut self, rows: u64) -> Result<bool> {
        if self.poll_attention().await? {
            self.finish_attention_and_ready(rows).await?;
            Ok(true)
        } else {
            let done = TokenDone::with_rows(rows);
            self.client
                .send(TdsBackendMessage::Token(BackendToken::Done(done)))
                .await?;
            Ok(false)
        }
    }
}
