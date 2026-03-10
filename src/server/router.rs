//! RPC routing infrastructure for system stored procedures.
//!
//! This module provides a flexible router for handling system stored procedure RPC requests.
//! It allows you to configure handlers for specific procedures (`sp_executesql`, `sp_prepare`,
//! `sp_execute`, `sp_unprepare`) while providing a fallback for unknown procedures.
//!
//! # Overview
//!
//! The [`SystemProcRouter`] dispatches incoming RPC requests to the appropriate handler based
//! on the procedure ID. This provides a clean separation of concerns and makes it easy to
//! compose handlers for different system procedures.
//!
//! # Example
//!
//! ```ignore
//! use tiberius::server::{
//!     SystemProcRouterBuilder, SpExecuteSqlHandler, SpPrepareHandler,
//!     SpExecuteHandler, SpUnprepareHandler, RejectUnknownProc,
//! };
//!
//! // Create handlers for each procedure type
//! let router = SystemProcRouterBuilder::new()
//!     .with_executesql(my_executesql_handler)
//!     .with_prepare(my_prepare_handler)
//!     .with_execute(my_execute_handler)
//!     .with_unprepare(my_unprepare_handler)
//!     .build();
//!
//! // Use the router as your RpcHandler
//! struct MyHandlers {
//!     rpc: SystemProcRouter<...>,
//!     // ...
//! }
//! ```
//!
//! # Fallback Handling
//!
//! By default, the router uses [`RejectUnknownProc`] as the fallback handler, which returns
//! an error for any unhandled procedure. You can provide a custom fallback handler using
//! [`SystemProcRouterBuilder::with_fallback`].
//!
//! ```ignore
//! let router = SystemProcRouterBuilder::new()
//!     .with_executesql(my_handler)
//!     .with_fallback(my_custom_fallback)
//!     .build();
//! ```

use crate::server::handler::{BoxFuture, RpcHandler, TdsClient};
use crate::server::messages::RpcMessage;
use crate::server::sp_executesql::{parse_executesql, SpExecuteSqlHandler};
use crate::server::sp_prepare::{
    parse_execute, parse_prepare, parse_unprepare, SpExecuteHandler, SpPrepareHandler,
    SpUnprepareHandler,
};
use crate::tds::codec::RpcProcId;
use crate::{Error, Result};

// =============================================================================
// RejectUnknownProc - Default fallback handler
// =============================================================================

/// Default fallback handler that rejects unknown procedures with an error.
///
/// This handler is used as the default fallback in [`SystemProcRouter`] when no
/// custom fallback is provided. It returns a protocol error for any RPC request
/// it receives.
///
/// # Example
///
/// ```ignore
/// use tiberius::server::RejectUnknownProc;
///
/// // RejectUnknownProc is automatically used when building without a custom fallback
/// let router = SystemProcRouterBuilder::new()
///     .with_executesql(my_handler)
///     .build();  // Uses RejectUnknownProc for unhandled procedures
/// ```
#[derive(Debug, Clone, Copy, Default)]
pub struct RejectUnknownProc;

impl RpcHandler for RejectUnknownProc {
    fn on_rpc<'a, C>(
        &'a self,
        _client: &'a mut C,
        message: RpcMessage,
    ) -> BoxFuture<'a, Result<()>>
    where
        C: TdsClient + 'a,
    {
        Box::pin(async move {
            let proc_name = if let Some(id) = message.proc_id {
                format!("proc_id {:?}", id)
            } else if let Some(name) = message.proc_name.as_deref() {
                format!("'{}'", name)
            } else {
                "<unknown>".to_string()
            };

            Err(Error::Protocol(
                format!("Unsupported RPC procedure: {}", proc_name).into(),
            ))
        })
    }
}

// =============================================================================
// SystemProcRouter - Main router struct
// =============================================================================

/// A router that dispatches RPC requests to appropriate handlers based on procedure ID.
///
/// The `SystemProcRouter` routes incoming RPC requests to specialized handlers for
/// common system stored procedures:
///
/// - `sp_executesql` (RpcProcId::ExecuteSQL) - parameterized query execution
/// - `sp_prepare` (RpcProcId::Prepare) - prepared statement preparation
/// - `sp_execute` (RpcProcId::Execute) - prepared statement execution
/// - `sp_unprepare` (RpcProcId::Unprepare) - prepared statement release
///
/// Any procedure not explicitly handled is delegated to the fallback handler.
///
/// # Type Parameters
///
/// - `ES` - Handler type for `sp_executesql` (implements [`SpExecuteSqlHandler`])
/// - `P` - Handler type for `sp_prepare` (implements [`SpPrepareHandler`])
/// - `E` - Handler type for `sp_execute` (implements [`SpExecuteHandler`])
/// - `U` - Handler type for `sp_unprepare` (implements [`SpUnprepareHandler`])
/// - `F` - Fallback handler type (implements [`RpcHandler`])
///
/// # Example
///
/// ```ignore
/// use tiberius::server::{SystemProcRouterBuilder, RpcHandler};
///
/// // Build a router with handlers for executesql and prepare
/// let router = SystemProcRouterBuilder::new()
///     .with_executesql(my_executesql_handler)
///     .with_prepare(my_prepare_handler)
///     .build();
///
/// // The router implements RpcHandler and can be used in TdsServerHandlers
/// ```
pub struct SystemProcRouter<ES, P, E, U, F> {
    /// Handler for sp_executesql requests.
    executesql: Option<ES>,
    /// Handler for sp_prepare requests.
    prepare: Option<P>,
    /// Handler for sp_execute requests.
    execute: Option<E>,
    /// Handler for sp_unprepare requests.
    unprepare: Option<U>,
    /// Fallback handler for unknown procedures.
    fallback: F,
}

impl<ES, P, E, U, F> SystemProcRouter<ES, P, E, U, F> {
    /// Creates a new `SystemProcRouter` with the given handlers.
    ///
    /// Prefer using [`SystemProcRouterBuilder`] for a more ergonomic construction.
    pub fn new(
        executesql: Option<ES>,
        prepare: Option<P>,
        execute: Option<E>,
        unprepare: Option<U>,
        fallback: F,
    ) -> Self {
        Self {
            executesql,
            prepare,
            execute,
            unprepare,
            fallback,
        }
    }

    /// Returns a reference to the sp_executesql handler, if set.
    pub fn executesql_handler(&self) -> Option<&ES> {
        self.executesql.as_ref()
    }

    /// Returns a mutable reference to the sp_executesql handler, if set.
    pub fn executesql_handler_mut(&mut self) -> Option<&mut ES> {
        self.executesql.as_mut()
    }

    /// Returns a reference to the sp_prepare handler, if set.
    pub fn prepare_handler(&self) -> Option<&P> {
        self.prepare.as_ref()
    }

    /// Returns a mutable reference to the sp_prepare handler, if set.
    pub fn prepare_handler_mut(&mut self) -> Option<&mut P> {
        self.prepare.as_mut()
    }

    /// Returns a reference to the sp_execute handler, if set.
    pub fn execute_handler(&self) -> Option<&E> {
        self.execute.as_ref()
    }

    /// Returns a mutable reference to the sp_execute handler, if set.
    pub fn execute_handler_mut(&mut self) -> Option<&mut E> {
        self.execute.as_mut()
    }

    /// Returns a reference to the sp_unprepare handler, if set.
    pub fn unprepare_handler(&self) -> Option<&U> {
        self.unprepare.as_ref()
    }

    /// Returns a mutable reference to the sp_unprepare handler, if set.
    pub fn unprepare_handler_mut(&mut self) -> Option<&mut U> {
        self.unprepare.as_mut()
    }

    /// Returns a reference to the fallback handler.
    pub fn fallback_handler(&self) -> &F {
        &self.fallback
    }

    /// Returns a mutable reference to the fallback handler.
    pub fn fallback_handler_mut(&mut self) -> &mut F {
        &mut self.fallback
    }

    /// Returns `true` if an sp_executesql handler is configured.
    pub fn has_executesql(&self) -> bool {
        self.executesql.is_some()
    }

    /// Returns `true` if an sp_prepare handler is configured.
    pub fn has_prepare(&self) -> bool {
        self.prepare.is_some()
    }

    /// Returns `true` if an sp_execute handler is configured.
    pub fn has_execute(&self) -> bool {
        self.execute.is_some()
    }

    /// Returns `true` if an sp_unprepare handler is configured.
    pub fn has_unprepare(&self) -> bool {
        self.unprepare.is_some()
    }
}

impl<ES, P, E, U, F> std::fmt::Debug for SystemProcRouter<ES, P, E, U, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SystemProcRouter")
            .field("has_executesql", &self.executesql.is_some())
            .field("has_prepare", &self.prepare.is_some())
            .field("has_execute", &self.execute.is_some())
            .field("has_unprepare", &self.unprepare.is_some())
            .field("fallback", &std::any::type_name::<F>())
            .finish()
    }
}

// Implement RpcHandler for SystemProcRouter
impl<ES, P, E, U, F> RpcHandler for SystemProcRouter<ES, P, E, U, F>
where
    ES: SpExecuteSqlHandler,
    P: SpPrepareHandler,
    E: SpExecuteHandler,
    U: SpUnprepareHandler,
    F: RpcHandler,
{
    fn on_rpc<'a, C>(
        &'a self,
        client: &'a mut C,
        message: RpcMessage,
    ) -> BoxFuture<'a, Result<()>>
    where
        C: TdsClient + 'a,
    {
        Box::pin(async move {
            match message.proc_id {
                Some(RpcProcId::ExecuteSQL) => {
                    if let Some(handler) = &self.executesql {
                        let param_set = message.into_param_set().await?;
                        let request = parse_executesql(param_set)?;
                        handler.execute(client, request).await
                    } else {
                        self.fallback.on_rpc(client, message).await
                    }
                }
                Some(RpcProcId::Prepare) => {
                    if let Some(handler) = &self.prepare {
                        let param_set = message.into_param_set().await?;
                        let request = parse_prepare(param_set)?;
                        // Handler is responsible for sending the output parameter and done tokens.
                        // The returned handle is for tracking purposes only.
                        let _handle = handler.prepare(client, request).await?;
                        Ok(())
                    } else {
                        self.fallback.on_rpc(client, message).await
                    }
                }
                Some(RpcProcId::Execute) => {
                    if let Some(handler) = &self.execute {
                        let param_set = message.into_param_set().await?;
                        let request = parse_execute(param_set)?;
                        handler.execute(client, request).await
                    } else {
                        self.fallback.on_rpc(client, message).await
                    }
                }
                Some(RpcProcId::Unprepare) => {
                    if let Some(handler) = &self.unprepare {
                        let param_set = message.into_param_set().await?;
                        let request = parse_unprepare(param_set)?;
                        handler.unprepare(client, request).await
                    } else {
                        self.fallback.on_rpc(client, message).await
                    }
                }
                // Unhandled system procedures delegate to fallback:
                // - PrepExec (RpcProcId::PrepExec = 13) - prepare + execute in one call
                // - CursorOpen, CursorFetch, CursorClose - cursor operations
                // - Named procedures (proc_name instead of proc_id)
                _ => self.fallback.on_rpc(client, message).await,
            }
        })
    }
}

// =============================================================================
// SystemProcRouterBuilder - Builder pattern
// =============================================================================

/// Builder for constructing a [`SystemProcRouter`].
///
/// This builder provides a fluent API for configuring RPC handlers for system stored
/// procedures. Each handler is optional; unset handlers will delegate to the fallback.
///
/// # Type Parameters
///
/// - `ES` - Handler type for `sp_executesql`
/// - `P` - Handler type for `sp_prepare`
/// - `E` - Handler type for `sp_execute`
/// - `U` - Handler type for `sp_unprepare`
/// - `F` - Fallback handler type
///
/// # Example
///
/// ```ignore
/// use tiberius::server::SystemProcRouterBuilder;
///
/// // Build a router with just executesql support
/// let router = SystemProcRouterBuilder::new()
///     .with_executesql(my_executesql_handler)
///     .build();
///
/// // Build a full router with all handlers
/// let full_router = SystemProcRouterBuilder::new()
///     .with_executesql(executesql_handler)
///     .with_prepare(prepare_handler)
///     .with_execute(execute_handler)
///     .with_unprepare(unprepare_handler)
///     .with_fallback(custom_fallback)
///     .build();
/// ```
pub struct SystemProcRouterBuilder<ES, P, E, U, F> {
    executesql: Option<ES>,
    prepare: Option<P>,
    execute: Option<E>,
    unprepare: Option<U>,
    fallback: F,
}

impl Default for SystemProcRouterBuilder<(), (), (), (), RejectUnknownProc> {
    fn default() -> Self {
        Self::new()
    }
}

impl SystemProcRouterBuilder<(), (), (), (), RejectUnknownProc> {
    /// Creates a new builder with no handlers and [`RejectUnknownProc`] as the fallback.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let builder = SystemProcRouterBuilder::new();
    /// ```
    pub fn new() -> Self {
        Self {
            executesql: None,
            prepare: None,
            execute: None,
            unprepare: None,
            fallback: RejectUnknownProc,
        }
    }
}

impl<ES, P, E, U, F> SystemProcRouterBuilder<ES, P, E, U, F> {
    /// Sets the handler for `sp_executesql` requests.
    ///
    /// The handler must implement [`SpExecuteSqlHandler`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// let router = SystemProcRouterBuilder::new()
    ///     .with_executesql(my_handler)
    ///     .build();
    /// ```
    pub fn with_executesql<H>(
        self,
        handler: H,
    ) -> SystemProcRouterBuilder<H, P, E, U, F>
    where
        H: SpExecuteSqlHandler,
    {
        SystemProcRouterBuilder {
            executesql: Some(handler),
            prepare: self.prepare,
            execute: self.execute,
            unprepare: self.unprepare,
            fallback: self.fallback,
        }
    }

    /// Sets the handler for `sp_prepare` requests.
    ///
    /// The handler must implement [`SpPrepareHandler`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// let router = SystemProcRouterBuilder::new()
    ///     .with_prepare(my_handler)
    ///     .build();
    /// ```
    pub fn with_prepare<H>(
        self,
        handler: H,
    ) -> SystemProcRouterBuilder<ES, H, E, U, F>
    where
        H: SpPrepareHandler,
    {
        SystemProcRouterBuilder {
            executesql: self.executesql,
            prepare: Some(handler),
            execute: self.execute,
            unprepare: self.unprepare,
            fallback: self.fallback,
        }
    }

    /// Sets the handler for `sp_execute` requests.
    ///
    /// The handler must implement [`SpExecuteHandler`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// let router = SystemProcRouterBuilder::new()
    ///     .with_execute(my_handler)
    ///     .build();
    /// ```
    pub fn with_execute<H>(
        self,
        handler: H,
    ) -> SystemProcRouterBuilder<ES, P, H, U, F>
    where
        H: SpExecuteHandler,
    {
        SystemProcRouterBuilder {
            executesql: self.executesql,
            prepare: self.prepare,
            execute: Some(handler),
            unprepare: self.unprepare,
            fallback: self.fallback,
        }
    }

    /// Sets the handler for `sp_unprepare` requests.
    ///
    /// The handler must implement [`SpUnprepareHandler`].
    ///
    /// # Example
    ///
    /// ```ignore
    /// let router = SystemProcRouterBuilder::new()
    ///     .with_unprepare(my_handler)
    ///     .build();
    /// ```
    pub fn with_unprepare<H>(
        self,
        handler: H,
    ) -> SystemProcRouterBuilder<ES, P, E, H, F>
    where
        H: SpUnprepareHandler,
    {
        SystemProcRouterBuilder {
            executesql: self.executesql,
            prepare: self.prepare,
            execute: self.execute,
            unprepare: Some(handler),
            fallback: self.fallback,
        }
    }

    /// Sets a custom fallback handler for unhandled RPC requests.
    ///
    /// The fallback handler receives any RPC request that doesn't match a configured
    /// procedure handler. By default, [`RejectUnknownProc`] is used.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let router = SystemProcRouterBuilder::new()
    ///     .with_executesql(my_handler)
    ///     .with_fallback(my_custom_fallback)
    ///     .build();
    /// ```
    pub fn with_fallback<H>(
        self,
        handler: H,
    ) -> SystemProcRouterBuilder<ES, P, E, U, H>
    where
        H: RpcHandler,
    {
        SystemProcRouterBuilder {
            executesql: self.executesql,
            prepare: self.prepare,
            execute: self.execute,
            unprepare: self.unprepare,
            fallback: handler,
        }
    }

    /// Builds the [`SystemProcRouter`] with the configured handlers.
    ///
    /// # Example
    ///
    /// ```ignore
    /// let router = SystemProcRouterBuilder::new()
    ///     .with_executesql(my_handler)
    ///     .build();
    /// ```
    pub fn build(self) -> SystemProcRouter<ES, P, E, U, F> {
        SystemProcRouter::new(
            self.executesql,
            self.prepare,
            self.execute,
            self.unprepare,
            self.fallback,
        )
    }
}

impl<ES, P, E, U, F> std::fmt::Debug for SystemProcRouterBuilder<ES, P, E, U, F> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SystemProcRouterBuilder")
            .field("has_executesql", &self.executesql.is_some())
            .field("has_prepare", &self.prepare.is_some())
            .field("has_execute", &self.execute.is_some())
            .field("has_unprepare", &self.unprepare.is_some())
            .field("fallback", &std::any::type_name::<F>())
            .finish()
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    // Simple test handler implementations for compile-time checks
    struct DummyExecuteSqlHandler;

    impl SpExecuteSqlHandler for DummyExecuteSqlHandler {
        fn execute<'a, C>(
            &'a self,
            _client: &'a mut C,
            _request: crate::server::sp_executesql::ParsedExecuteSql<'a>,
        ) -> BoxFuture<'a, Result<()>>
        where
            C: TdsClient + 'a,
        {
            Box::pin(async { Ok(()) })
        }
    }

    struct DummyPrepareHandler;

    impl SpPrepareHandler for DummyPrepareHandler {
        fn prepare<'a, C>(
            &'a self,
            _client: &'a mut C,
            _request: crate::server::sp_prepare::ParsedPrepare<'a>,
        ) -> BoxFuture<'a, Result<crate::server::prepared::PreparedHandle>>
        where
            C: TdsClient + 'a,
        {
            Box::pin(async { Ok(crate::server::prepared::PreparedHandle::from_i32(1)) })
        }
    }

    struct DummyExecuteHandler;

    impl SpExecuteHandler for DummyExecuteHandler {
        fn execute<'a, C>(
            &'a self,
            _client: &'a mut C,
            _request: crate::server::sp_prepare::ParsedExecute<'a>,
        ) -> BoxFuture<'a, Result<()>>
        where
            C: TdsClient + 'a,
        {
            Box::pin(async { Ok(()) })
        }
    }

    struct DummyUnprepareHandler;

    impl SpUnprepareHandler for DummyUnprepareHandler {
        fn unprepare<'a, C>(
            &'a self,
            _client: &'a mut C,
            _request: crate::server::sp_prepare::ParsedUnprepare,
        ) -> BoxFuture<'a, Result<()>>
        where
            C: TdsClient + 'a,
        {
            Box::pin(async { Ok(()) })
        }
    }

    struct DummyFallbackHandler;

    impl RpcHandler for DummyFallbackHandler {
        fn on_rpc<'a, C>(
            &'a self,
            _client: &'a mut C,
            _message: RpcMessage,
        ) -> BoxFuture<'a, Result<()>>
        where
            C: TdsClient + 'a,
        {
            Box::pin(async { Ok(()) })
        }
    }

    #[test]
    fn test_builder_default() {
        let builder = SystemProcRouterBuilder::new();
        let router = builder.build();

        assert!(!router.has_executesql());
        assert!(!router.has_prepare());
        assert!(!router.has_execute());
        assert!(!router.has_unprepare());
    }

    #[test]
    fn test_builder_with_executesql() {
        let router = SystemProcRouterBuilder::new()
            .with_executesql(DummyExecuteSqlHandler)
            .build();

        assert!(router.has_executesql());
        assert!(!router.has_prepare());
        assert!(!router.has_execute());
        assert!(!router.has_unprepare());
    }

    #[test]
    fn test_builder_with_all_handlers() {
        let router = SystemProcRouterBuilder::new()
            .with_executesql(DummyExecuteSqlHandler)
            .with_prepare(DummyPrepareHandler)
            .with_execute(DummyExecuteHandler)
            .with_unprepare(DummyUnprepareHandler)
            .build();

        assert!(router.has_executesql());
        assert!(router.has_prepare());
        assert!(router.has_execute());
        assert!(router.has_unprepare());
    }

    #[test]
    fn test_builder_with_custom_fallback() {
        let router = SystemProcRouterBuilder::new()
            .with_executesql(DummyExecuteSqlHandler)
            .with_fallback(DummyFallbackHandler)
            .build();

        assert!(router.has_executesql());
        // Verify fallback is set (can't check type at runtime easily, but it compiles)
    }

    #[test]
    fn test_router_accessors() {
        let router = SystemProcRouterBuilder::new()
            .with_executesql(DummyExecuteSqlHandler)
            .with_prepare(DummyPrepareHandler)
            .with_execute(DummyExecuteHandler)
            .with_unprepare(DummyUnprepareHandler)
            .build();

        // Test immutable accessors
        assert!(router.executesql_handler().is_some());
        assert!(router.prepare_handler().is_some());
        assert!(router.execute_handler().is_some());
        assert!(router.unprepare_handler().is_some());
        let _ = router.fallback_handler();
    }

    #[test]
    fn test_router_mutable_accessors() {
        let mut router = SystemProcRouterBuilder::new()
            .with_executesql(DummyExecuteSqlHandler)
            .with_prepare(DummyPrepareHandler)
            .with_execute(DummyExecuteHandler)
            .with_unprepare(DummyUnprepareHandler)
            .build();

        // Test mutable accessors
        assert!(router.executesql_handler_mut().is_some());
        assert!(router.prepare_handler_mut().is_some());
        assert!(router.execute_handler_mut().is_some());
        assert!(router.unprepare_handler_mut().is_some());
        let _ = router.fallback_handler_mut();
    }

    #[test]
    fn test_router_debug() {
        let router = SystemProcRouterBuilder::new()
            .with_executesql(DummyExecuteSqlHandler)
            .build();

        let debug_str = format!("{:?}", router);
        assert!(debug_str.contains("SystemProcRouter"));
        assert!(debug_str.contains("has_executesql"));
    }

    #[test]
    fn test_builder_debug() {
        let builder = SystemProcRouterBuilder::new()
            .with_executesql(DummyExecuteSqlHandler);

        let debug_str = format!("{:?}", builder);
        assert!(debug_str.contains("SystemProcRouterBuilder"));
    }

    #[test]
    fn test_reject_unknown_proc_default() {
        let handler = RejectUnknownProc::default();
        let _ = format!("{:?}", handler);
    }
}
