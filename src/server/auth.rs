//! Authentication helpers for the TDS server.

use std::collections::HashMap;
use std::fmt::Debug;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use futures_util::sink::{Sink, SinkExt};

use crate::server::handler::{AuthHandler, TdsClientInfo};
use crate::server::messages::{BackendToken, TdsBackendMessage};
use crate::server::state::TdsConnectionState;
use crate::tds::codec::{
    DoneStatus, FeatureAck, FedAuthAck, FeatureLevel, TokenDone, TokenEnvChange,
    TokenFedAuthInfo, TokenFeatureExtAck, TokenLoginAck,
};
use crate::{Collation, EncryptionLevel, Error, LoginMessage, Result};

type AuthResult<T> = std::result::Result<T, AuthError>;

/// Metadata key for the authenticated user name.
pub const METADATA_USER: &str = "user";
/// Metadata key for the requested database.
pub const METADATA_DATABASE: &str = "database";
/// Metadata key for the client application name.
pub const METADATA_APPLICATION: &str = "application";
/// Metadata key for the server name.
pub const METADATA_SERVER: &str = "server";

/// Authenticated login context derived from a LOGIN7 packet.
#[derive(Debug, Clone)]
pub struct LoginInfo {
    user: Option<String>,
    database: Option<String>,
    application: Option<String>,
    server: Option<String>,
    client_addr: SocketAddr,
    tds_version: FeatureLevel,
}

impl LoginInfo {
    pub fn from_login<C>(client: &C, login: &LoginMessage<'_>) -> Self
    where
        C: TdsClientInfo,
    {
        let user = login.user_name_ref().trim();
        let database = login.db_name_ref().trim();
        let application = login.app_name_ref().trim();
        let server = login.server_name_ref().trim();

        Self {
            user: if user.is_empty() { None } else { Some(user.to_string()) },
            database: if database.is_empty() {
                None
            } else {
                Some(database.to_string())
            },
            application: if application.is_empty() {
                None
            } else {
                Some(application.to_string())
            },
            server: if server.is_empty() {
                None
            } else {
                Some(server.to_string())
            },
            client_addr: client.socket_addr(),
            tds_version: login.tds_version(),
        }
    }

    pub fn user(&self) -> Option<&str> {
        self.user.as_deref()
    }

    pub fn database(&self) -> Option<&str> {
        self.database.as_deref()
    }

    pub fn application(&self) -> Option<&str> {
        self.application.as_deref()
    }

    pub fn server(&self) -> Option<&str> {
        self.server.as_deref()
    }

    pub fn client_addr(&self) -> SocketAddr {
        self.client_addr
    }

    pub fn tds_version(&self) -> FeatureLevel {
        self.tds_version
    }

    fn apply_metadata<C>(&self, client: &mut C, session_user: Option<&str>)
    where
        C: TdsClientInfo,
    {
        let metadata = client.metadata_mut();
        if let Some(user) = session_user.or(self.user()) {
            metadata.insert(METADATA_USER.to_string(), user.to_string());
        }
        if let Some(db) = self.database() {
            metadata.insert(METADATA_DATABASE.to_string(), db.to_string());
        }
        if let Some(app) = self.application() {
            metadata.insert(METADATA_APPLICATION.to_string(), app.to_string());
        }
        if let Some(server) = self.server() {
            metadata.insert(METADATA_SERVER.to_string(), server.to_string());
        }
    }
}

/// Auth success details, allowing the handler to override the session user.
#[derive(Debug, Clone, Default)]
pub struct AuthSuccess {
    pub session_user: Option<String>,
}

/// Authentication error that maps to a login failure.
#[derive(Debug, Clone)]
pub struct AuthError {
    pub code: u32,
    pub state: u8,
    pub class: u8,
    pub message: String,
}

impl AuthError {
    pub fn login_failed(user: Option<&str>) -> Self {
        let message = match user {
            Some(user) if !user.is_empty() => format!("Login failed for user '{user}'."),
            _ => "Login failed.".to_string(),
        };

        Self {
            code: 18456,
            state: 1,
            class: 14,
            message,
        }
    }
}

/// Validate SQL Server username/password authentication.
#[async_trait]
pub trait SqlAuthSource: Send + Sync + Debug {
    async fn authenticate(&self, login: &LoginInfo, password: &str) -> AuthResult<AuthSuccess>;
}

/// Validate FedAuth/AAD bearer tokens.
#[async_trait]
pub trait FedAuthValidator: Send + Sync + Debug {
    async fn validate(&self, login: &LoginInfo, token: &str) -> AuthResult<AuthSuccess>;
}

/// A single SSPI step response.
#[derive(Debug)]
pub struct SspiStep {
    pub response: Option<Vec<u8>>,
    pub complete: bool,
    pub session_user: Option<String>,
}

/// A stateful SSPI session for integrated authentication.
pub trait SspiSession: Send {
    fn step(&mut self, token: &[u8]) -> AuthResult<SspiStep>;
}

/// Result of initializing an SSPI session.
pub struct SspiStart {
    pub step: SspiStep,
    pub session: Option<Box<dyn SspiSession>>,
}

/// SSPI acceptor used to start integrated authentication.
pub trait SspiAcceptor: Send + Sync + Debug {
    fn start(&self, login: &LoginInfo, token: &[u8]) -> AuthResult<SspiStart>;
}

/// Default login token provider (LoginAck + EnvChange + Done).
#[derive(Debug, Clone)]
pub struct DefaultEnvChangeProvider {
    pub program_name: String,
    pub server_version: u32,
    pub collation: Collation,
    pub default_database: String,
}

impl Default for DefaultEnvChangeProvider {
    fn default() -> Self {
        Self {
            program_name: "tiberius".to_string(),
            server_version: 0,
            collation: Collation::new(13632521, 52),
            default_database: "master".to_string(),
        }
    }
}

/// Supplies login ack and initial envchange tokens.
pub trait EnvChangeProvider: Send + Sync + Debug {
    fn login_ack(&self, login: &LoginMessage<'_>) -> TokenLoginAck;

    fn env_changes<C>(&self, client: &C, login: &LoginMessage<'_>) -> Vec<TokenEnvChange>
    where
        C: TdsClientInfo;

    fn feature_ext_ack(&self, _login: &LoginMessage<'_>) -> Option<TokenFeatureExtAck> {
        None
    }

    fn fed_auth_info<C>(&self, _client: &C, _login: &LoginMessage<'_>) -> Option<TokenFedAuthInfo>
    where
        C: TdsClientInfo,
    {
        None
    }
}

impl DefaultEnvChangeProvider {
    pub fn login_ack(&self, login: &LoginMessage<'_>) -> TokenLoginAck {
        TokenLoginAck::new(1, login.tds_version(), &self.program_name, self.server_version)
    }

    pub fn env_changes<C>(&self, client: &C, login: &LoginMessage<'_>) -> Vec<TokenEnvChange>
    where
        C: TdsClientInfo,
    {
        let db_name = login.db_name_ref().trim();
        let db_name = if db_name.is_empty() {
            self.default_database.as_str()
        } else {
            db_name
        };

        vec![
            TokenEnvChange::Database(db_name.to_string(), String::new()),
            TokenEnvChange::PacketSize(login.packet_size(), client.packet_size()),
            TokenEnvChange::SqlCollation {
                old: None,
                new: Some(self.collation),
            },
        ]
    }

    pub fn feature_ext_ack(&self, login: &LoginMessage<'_>) -> Option<TokenFeatureExtAck> {
        if login.has_feature_ext() {
            let mut features = Vec::new();
            if login.fed_auth_token().is_some() {
                features.push(FeatureAck::FedAuth(FedAuthAck::SecurityToken {
                    nonce: login.fed_auth_nonce(),
                }));
            }

            Some(TokenFeatureExtAck { features })
        } else {
            None
        }
    }
}

impl EnvChangeProvider for DefaultEnvChangeProvider {
    fn login_ack(&self, login: &LoginMessage<'_>) -> TokenLoginAck {
        self.login_ack(login)
    }

    fn env_changes<C>(&self, client: &C, login: &LoginMessage<'_>) -> Vec<TokenEnvChange>
    where
        C: TdsClientInfo,
    {
        self.env_changes(client, login)
    }

    fn feature_ext_ack(&self, login: &LoginMessage<'_>) -> Option<TokenFeatureExtAck> {
        self.feature_ext_ack(login)
    }
}

fn negotiate_encryption(
    server_policy: EncryptionLevel,
    client_request: EncryptionLevel,
) -> EncryptionLevel {
    match server_policy {
        EncryptionLevel::NotSupported => EncryptionLevel::NotSupported,
        EncryptionLevel::Required => EncryptionLevel::Required,
        EncryptionLevel::On => match client_request {
            EncryptionLevel::Required | EncryptionLevel::On => EncryptionLevel::On,
            EncryptionLevel::Off => EncryptionLevel::Off,
            EncryptionLevel::NotSupported => EncryptionLevel::NotSupported,
        },
        EncryptionLevel::Off => match client_request {
            EncryptionLevel::NotSupported => EncryptionLevel::NotSupported,
            _ => EncryptionLevel::Off,
        },
    }
}

struct AuthSession {
    login: LoginMessage<'static>,
    info: LoginInfo,
    sspi: Box<dyn SspiSession>,
}

/// Builder for composing authentication methods.
#[derive(Debug)]
pub struct AuthBuilder<P = DefaultEnvChangeProvider> {
    env_provider: P,
    encryption: EncryptionLevel,
    sql_auth: Option<Arc<dyn SqlAuthSource>>,
    sspi: Option<Arc<dyn SspiAcceptor>>,
    fed_auth: Option<Arc<dyn FedAuthValidator>>,
    allow_trust: bool,
}

impl Default for AuthBuilder<DefaultEnvChangeProvider> {
    fn default() -> Self {
        Self {
            env_provider: DefaultEnvChangeProvider::default(),
            encryption: EncryptionLevel::NotSupported,
            sql_auth: None,
            sspi: None,
            fed_auth: None,
            allow_trust: false,
        }
    }
}

impl<P> AuthBuilder<P>
where
    P: EnvChangeProvider + 'static,
{
    pub fn new(env_provider: P) -> Self {
        Self {
            env_provider,
            encryption: EncryptionLevel::NotSupported,
            sql_auth: None,
            sspi: None,
            fed_auth: None,
            allow_trust: false,
        }
    }

    pub fn encryption(mut self, encryption: EncryptionLevel) -> Self {
        self.encryption = encryption;
        self
    }

    pub fn with_sql_auth(mut self, auth: Arc<dyn SqlAuthSource>) -> Self {
        self.sql_auth = Some(auth);
        self
    }

    pub fn with_sspi(mut self, acceptor: Arc<dyn SspiAcceptor>) -> Self {
        self.sspi = Some(acceptor);
        self
    }

    pub fn with_fed_auth(mut self, validator: Arc<dyn FedAuthValidator>) -> Self {
        self.fed_auth = Some(validator);
        self
    }

    pub fn allow_trust(mut self) -> Self {
        self.allow_trust = true;
        self
    }

    pub fn build(self) -> TdsAuthHandler<P> {
        TdsAuthHandler {
            env_provider: self.env_provider,
            encryption: self.encryption,
            sql_auth: self.sql_auth,
            sspi: self.sspi,
            fed_auth: self.fed_auth,
            allow_trust: self.allow_trust,
            sessions: Mutex::new(HashMap::new()),
        }
    }
}

/// Auth handler that multiplexes SQL auth, SSPI, and FedAuth flows.
pub struct TdsAuthHandler<P = DefaultEnvChangeProvider> {
    env_provider: P,
    encryption: EncryptionLevel,
    sql_auth: Option<Arc<dyn SqlAuthSource>>,
    sspi: Option<Arc<dyn SspiAcceptor>>,
    fed_auth: Option<Arc<dyn FedAuthValidator>>,
    allow_trust: bool,
    sessions: Mutex<HashMap<SocketAddr, AuthSession>>,
}

impl<P> TdsAuthHandler<P>
where
    P: EnvChangeProvider + 'static,
{
    async fn finish_login<C>(
        &self,
        client: &mut C,
        login: &LoginMessage<'_>,
        info: &LoginInfo,
        session_user: Option<&str>,
    ) -> Result<()>
    where
        C: TdsClientInfo + Sink<TdsBackendMessage, Error = Error> + Unpin + Send,
    {
        client.set_tds_version(login.tds_version());
        info.apply_metadata(client, session_user);

        let mut tokens = Vec::new();
        tokens.push(BackendToken::LoginAck(self.env_provider.login_ack(login)));
        if let Some(feature) = self.env_provider.feature_ext_ack(login) {
            tokens.push(BackendToken::FeatureExtAck(feature));
        }
        if let Some(fed_auth) = self.env_provider.fed_auth_info(client, login) {
            tokens.push(BackendToken::FedAuthInfo(fed_auth));
        }
        for env in self.env_provider.env_changes(client, login) {
            tokens.push(BackendToken::EnvChange(env));
        }
        tokens.push(BackendToken::Done(TokenDone::default()));

        client.send(TdsBackendMessage::Tokens(tokens)).await?;
        client.set_packet_size(login.packet_size());
        client.set_state(TdsConnectionState::ReadyForQuery);
        Ok(())
    }

    async fn send_login_error<C>(
        &self,
        client: &mut C,
        login: Option<&LoginInfo>,
        err: AuthError,
    ) -> Result<()>
    where
        C: TdsClientInfo + Sink<TdsBackendMessage, Error = Error> + Unpin + Send,
    {
        let server = login
            .and_then(|info| info.server())
            .map(|s| s.to_string())
            .unwrap_or_else(|| client.socket_addr().ip().to_string());
        let token = crate::TokenError::new(
            err.code,
            err.state,
            err.class,
            err.message,
            server,
            "",
            1,
        );
        let done = TokenDone::with_status(DoneStatus::Error.into(), 0);

        client
            .send(TdsBackendMessage::Tokens(vec![
                BackendToken::Error(token),
                BackendToken::Done(done),
            ]))
            .await?;

        client.set_state(TdsConnectionState::Closed);
        Ok(())
    }

    async fn handle_sspi_step<C>(
        &self,
        client: &mut C,
        login: &LoginMessage<'_>,
        info: &LoginInfo,
        step: SspiStep,
    ) -> Result<()>
    where
        C: TdsClientInfo + Sink<TdsBackendMessage, Error = Error> + Unpin + Send,
    {
        if let Some(response) = step.response {
            client
                .send(TdsBackendMessage::Token(BackendToken::Sspi(
                    crate::tds::codec::TokenSspi::from_bytes(response),
                )))
                .await?;
        } else if !step.complete {
            client
                .send(TdsBackendMessage::Token(BackendToken::Sspi(
                    crate::tds::codec::TokenSspi::from_bytes(Vec::new()),
                )))
                .await?;
        }

        if step.complete {
            self.finish_login(client, login, info, step.session_user.as_deref())
                .await?;
        } else {
            client.set_state(TdsConnectionState::AuthenticationInProgress);
        }

        Ok(())
    }
}

impl<P> AuthHandler for TdsAuthHandler<P>
where
    P: EnvChangeProvider + 'static,
{
    fn on_prelogin<'a, C>(
        &'a self,
        client: &'a mut C,
        message: crate::tds::codec::PreloginMessage,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>
    where
        C: TdsClientInfo + futures_util::sink::Sink<TdsBackendMessage, Error = Error> + Unpin + Send + 'a,
    {
        Box::pin(async move {
            let mut reply = crate::tds::codec::PreloginMessage::new();
            let negotiated = negotiate_encryption(self.encryption, message.encryption);
            reply.encryption = negotiated;
            reply.instance_name = None;
            reply.version = message.version;
            reply.sub_build = message.sub_build;
            reply.thread_id = 0;
            reply.fed_auth_required = message.fed_auth_required && self.fed_auth.is_some();
            reply.nonce = None;

            let prelogin_packet = match reply.encryption {
                EncryptionLevel::Off | EncryptionLevel::NotSupported => "tabular",
                _ => "prelogin",
            };
            client
                .metadata_mut()
                .insert("prelogin_packet_type".into(), prelogin_packet.into());

            client.set_encryption(reply.encryption);
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
        C: TdsClientInfo + futures_util::sink::Sink<TdsBackendMessage, Error = Error> + Unpin + Send + 'a,
    {
        Box::pin(async move {
            let info = LoginInfo::from_login(client, &message);
            client.set_tds_version(message.tds_version());

            if let Some(token) = message.fed_auth_token() {
                let Some(validator) = self.fed_auth.as_ref() else {
                    return self
                        .send_login_error(
                            client,
                            Some(&info),
                            AuthError::login_failed(info.user()),
                        )
                        .await;
                };

                match validator.validate(&info, token).await {
                    Ok(success) => {
                        return self
                            .finish_login(
                                client,
                                &message,
                                &info,
                                success.session_user.as_deref(),
                            )
                            .await;
                    }
                    Err(err) => {
                        return self.send_login_error(client, Some(&info), err).await;
                    }
                }
            }

            if let Some(initial) = message.integrated_security_bytes() {
                let Some(acceptor) = self.sspi.as_ref() else {
                    return self
                        .send_login_error(
                            client,
                            Some(&info),
                            AuthError::login_failed(info.user()),
                        )
                        .await;
                };

                match acceptor.start(&info, initial) {
                    Ok(start) => {
                        if let Some(session) = start.session {
                            let mut sessions = self.sessions.lock().unwrap();
                            sessions.insert(
                                client.socket_addr(),
                                AuthSession {
                                    login: message.clone(),
                                    info: info.clone(),
                                    sspi: session,
                                },
                            );
                        }

                        return self
                            .handle_sspi_step(client, &message, &info, start.step)
                            .await;
                    }
                    Err(err) => {
                        return self.send_login_error(client, Some(&info), err).await;
                    }
                }
            }

            if let Some(sql_auth) = self.sql_auth.as_ref() {
                let password = message.password_ref();
                match sql_auth.authenticate(&info, password).await {
                    Ok(success) => {
                        return self
                            .finish_login(
                                client,
                                &message,
                                &info,
                                success.session_user.as_deref(),
                            )
                            .await;
                    }
                    Err(err) => {
                        return self.send_login_error(client, Some(&info), err).await;
                    }
                }
            }

            if self.allow_trust {
                return self.finish_login(client, &message, &info, info.user()).await;
            }

            self.send_login_error(client, Some(&info), AuthError::login_failed(info.user()))
                .await
        })
    }

    fn on_sspi<'a, C>(
        &'a self,
        client: &'a mut C,
        token: crate::tds::codec::TokenSspi,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>
    where
        C: TdsClientInfo + futures_util::sink::Sink<TdsBackendMessage, Error = Error> + Unpin + Send + 'a,
    {
        Box::pin(async move {
            let addr = client.socket_addr();
            let session = {
                let mut sessions = self.sessions.lock().unwrap();
                sessions.remove(&addr)
            };

            let Some(mut session) = session else {
                return self
                    .send_login_error(
                        client,
                        None,
                        AuthError::login_failed(None),
                    )
                    .await;
            };

            let step = match session.sspi.step(token.as_ref()) {
                Ok(step) => step,
                Err(err) => {
                    return self.send_login_error(client, Some(&session.info), err).await;
                }
            };

            let login = session.login.clone();
            let info = session.info.clone();

            if !step.complete {
                let mut sessions = self.sessions.lock().unwrap();
                sessions.insert(addr, session);
            }

            self.handle_sspi_step(client, &login, &info, step)
                .await
        })
    }
}

#[cfg(all(unix, feature = "integrated-auth-gssapi"))]
pub mod gssapi {
    use super::{AuthError, AuthResult, LoginInfo, SspiAcceptor, SspiSession, SspiStart, SspiStep};
    use libgssapi::context::{SecurityContext, ServerCtx};
    use libgssapi::credential::{Cred, CredUsage};
    use libgssapi::oid::{OidSet, GSS_MECH_KRB5};

    #[derive(Debug, Default)]
    pub struct GssapiAcceptor;

    impl GssapiAcceptor {
        pub fn new() -> Self {
            Self
        }
    }

    impl SspiAcceptor for GssapiAcceptor {
        fn start(&self, _login: &LoginInfo, token: &[u8]) -> AuthResult<SspiStart> {
            let mut mechs = OidSet::new().map_err(|err| AuthError {
                code: 18456,
                state: 1,
                class: 14,
                message: format!("SSPI: {err}"),
            })?;
            mechs.add(&GSS_MECH_KRB5).map_err(|err| AuthError {
                code: 18456,
                state: 1,
                class: 14,
                message: format!("SSPI: {err}"),
            })?;

            let cred = Cred::acquire(None, None, CredUsage::Accept, Some(&mechs)).map_err(|err| {
                AuthError {
                    code: 18456,
                    state: 1,
                    class: 14,
                    message: format!("SSPI: {err}"),
                }
            })?;

            let mut ctx = ServerCtx::new(Some(cred));
            let response = ctx.step(token).map_err(|err| AuthError {
                code: 18456,
                state: 1,
                class: 14,
                message: format!("SSPI: {err}"),
            })?;

            let complete = ctx.is_complete();
            let session_user = if complete {
                ctx.source_name()
                    .ok()
                    .map(|name| name.to_string())
            } else {
                None
            };

            let step = SspiStep {
                response: response.map(|buf| buf.to_vec()),
                complete,
                session_user,
            };

            let session = if complete {
                None
            } else {
                Some(Box::new(GssapiSession { ctx }) as Box<dyn SspiSession>)
            };

            Ok(SspiStart { step, session })
        }
    }

    #[derive(Debug)]
    struct GssapiSession {
        ctx: ServerCtx,
    }

    impl SspiSession for GssapiSession {
        fn step(&mut self, token: &[u8]) -> AuthResult<SspiStep> {
            let response = self.ctx.step(token).map_err(|err| AuthError {
                code: 18456,
                state: 1,
                class: 14,
                message: format!("SSPI: {err}"),
            })?;
            let complete = self.ctx.is_complete();
            let session_user = if complete {
                self.ctx
                    .source_name()
                    .ok()
                    .map(|name| name.to_string())
            } else {
                None
            };

            Ok(SspiStep {
                response: response.map(|buf| buf.to_vec()),
                complete,
                session_user,
            })
        }
    }
}
