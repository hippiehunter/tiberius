//! Helpers for streaming resultsets efficiently.

use futures_util::sink::SinkExt;

use crate::server::handler::TdsClientInfo;
use crate::server::messages::{BackendToken, TdsBackendMessage};
use crate::tds::codec::{ColumnData, MetaDataColumn, TokenColMetaData, TokenDone, TokenRow};
use crate::Result;
use bytes::BytesMut;

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
        client.send(TdsBackendMessage::Token(BackendToken::ColMetaData(token))).await?;

        Ok(Self { client, columns })
    }

    /// Send a single row.
    pub async fn send_row(&mut self, row: TokenRow<'static>) -> Result<()> {
        let _ = &self.columns;
        self.client
            .send(TdsBackendMessage::Token(BackendToken::Row(row)))
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
            .send(TdsBackendMessage::TokenBytes(payload))
            .await
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
            .send(TdsBackendMessage::TokenBytes(payload))
            .await
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

    /// Finish the resultset with a DONEINPROC token.
    pub async fn finish_in_proc(self, rows: u64) -> Result<()> {
        let done = TokenDone::with_rows(rows);
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
}
