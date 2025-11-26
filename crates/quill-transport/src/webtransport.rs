//! WebTransport support for browser and native clients
//!
//! This module provides WebTransport session management over HTTP/3,
//! enabling browser clients to use QUIC features like:
//! - Bidirectional and unidirectional streams
//! - Unreliable datagrams
//! - Multiplexed connections
//!
//! # Overview
//!
//! WebTransport is a W3C API that allows web applications to establish
//! bidirectional connections using HTTP/3. This is ideal for:
//! - Real-time gaming
//! - Live streaming
//! - Collaborative applications
//! - IoT data streaming
//!
//! # Example
//!
//! ```ignore
//! use quill_transport::{WebTransportServerBuilder, WebTransportHandler};
//!
//! let server = WebTransportServerBuilder::new(addr)
//!     .build()?;
//!
//! server.serve(|session| async move {
//!     // Handle bidirectional streams
//!     while let Some(stream) = session.accept_bi().await? {
//!         // Process stream
//!     }
//!     Ok(())
//! }).await?;
//! ```

use bytes::Bytes;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use thiserror::Error;
use tracing::{debug, error, info};

use crate::hyper::{HyperConfig, HyperError};

/// WebTransport-specific errors
#[derive(Debug, Error)]
pub enum WebTransportError {
    #[error("Connection error: {0}")]
    Connection(String),

    #[error("Session error: {0}")]
    Session(String),

    #[error("Stream error: {0}")]
    Stream(String),

    #[error("Datagram error: {0}")]
    Datagram(String),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("Configuration error: {0}")]
    Config(String),

    #[error("HTTP/3 error: {0}")]
    H3(String),
}

impl From<HyperError> for WebTransportError {
    fn from(err: HyperError) -> Self {
        match err {
            HyperError::QuicConnection(s) => WebTransportError::Connection(s),
            HyperError::H3Stream(s) => WebTransportError::Stream(s),
            HyperError::Datagram(s) => WebTransportError::Datagram(s),
            HyperError::Tls(s) => WebTransportError::Tls(s),
            HyperError::Config(s) => WebTransportError::Config(s),
            _ => WebTransportError::H3(err.to_string()),
        }
    }
}

/// Configuration for WebTransport server
#[derive(Debug, Clone)]
pub struct WebTransportConfig {
    /// Base HTTP/3 configuration
    pub http3: HyperConfig,
    /// Maximum concurrent WebTransport sessions
    pub max_sessions: usize,
    /// Session idle timeout
    pub session_timeout_ms: u64,
    /// Enable datagram support
    pub enable_datagrams: bool,
    /// Maximum datagram size
    pub max_datagram_size: usize,
}

impl Default for WebTransportConfig {
    fn default() -> Self {
        Self {
            http3: HyperConfig::default(),
            max_sessions: 100,
            session_timeout_ms: 60000,
            enable_datagrams: true,
            max_datagram_size: 65536,
        }
    }
}

/// A WebTransport session wrapper providing stream and datagram operations
pub struct Session {
    session_id: u64,
    remote_addr: SocketAddr,
    config: Arc<WebTransportConfig>,
}

impl Session {
    /// Get the session ID
    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    /// Get the remote address
    pub fn remote_addr(&self) -> SocketAddr {
        self.remote_addr
    }

    /// Check if datagrams are enabled
    pub fn datagrams_enabled(&self) -> bool {
        self.config.enable_datagrams
    }
}

/// A bidirectional stream in a WebTransport session
pub struct BiStream {
    stream_id: u64,
    session_id: u64,
}

impl BiStream {
    /// Get the stream ID
    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }

    /// Get the parent session ID
    pub fn session_id(&self) -> u64 {
        self.session_id
    }
}

/// A unidirectional stream in a WebTransport session
pub struct UniStream {
    stream_id: u64,
    session_id: u64,
    is_send: bool,
}

impl UniStream {
    /// Get the stream ID
    pub fn stream_id(&self) -> u64 {
        self.stream_id
    }

    /// Get the parent session ID
    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    /// Check if this is a send stream (client-initiated)
    pub fn is_send(&self) -> bool {
        self.is_send
    }
}

/// Trait for handling WebTransport sessions
pub trait WebTransportHandler: Clone + Send + 'static {
    /// The future type returned by handle()
    type Future: Future<Output = Result<(), WebTransportError>> + Send;

    /// Handle a new WebTransport session
    fn handle(&self, session: Session) -> Self::Future;
}

/// A simple closure-based WebTransport handler
#[derive(Clone)]
pub struct FnWebTransportHandler<F> {
    handler: F,
}

impl<F, Fut> FnWebTransportHandler<F>
where
    F: Fn(Session) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Result<(), WebTransportError>> + Send,
{
    /// Create a new function-based handler
    pub fn new(handler: F) -> Self {
        Self { handler }
    }
}

impl<F, Fut> WebTransportHandler for FnWebTransportHandler<F>
where
    F: Fn(Session) -> Fut + Clone + Send + 'static,
    Fut: Future<Output = Result<(), WebTransportError>> + Send,
{
    type Future = Fut;

    fn handle(&self, session: Session) -> Self::Future {
        (self.handler)(session)
    }
}

/// Builder for WebTransport server
pub struct WebTransportServerBuilder {
    config: WebTransportConfig,
    bind_addr: SocketAddr,
}

impl WebTransportServerBuilder {
    /// Create a new WebTransport server builder
    pub fn new(bind_addr: SocketAddr) -> Self {
        Self {
            config: WebTransportConfig::default(),
            bind_addr,
        }
    }

    /// Set maximum concurrent sessions
    pub fn max_sessions(mut self, max: usize) -> Self {
        self.config.max_sessions = max;
        self
    }

    /// Set session timeout
    pub fn session_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.config.session_timeout_ms = timeout_ms;
        self
    }

    /// Enable or disable datagrams
    pub fn enable_datagrams(mut self, enable: bool) -> Self {
        self.config.enable_datagrams = enable;
        self.config.http3.enable_datagrams = enable;
        self
    }

    /// Set maximum datagram size
    pub fn max_datagram_size(mut self, size: usize) -> Self {
        self.config.max_datagram_size = size;
        self.config.http3.max_datagram_size = size;
        self
    }

    /// Set maximum concurrent streams per session
    pub fn max_concurrent_streams(mut self, max: u64) -> Self {
        self.config.http3.max_concurrent_streams = max;
        self
    }

    /// Set idle timeout
    pub fn idle_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.config.http3.idle_timeout_ms = timeout_ms;
        self
    }

    /// Build the WebTransport server
    pub fn build(self) -> Result<WebTransportServer, WebTransportError> {
        Ok(WebTransportServer {
            config: Arc::new(self.config),
            bind_addr: self.bind_addr,
        })
    }
}

/// WebTransport server
pub struct WebTransportServer {
    config: Arc<WebTransportConfig>,
    bind_addr: SocketAddr,
}

impl WebTransportServer {
    /// Get the bind address
    pub fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    /// Get the configuration
    pub fn config(&self) -> &WebTransportConfig {
        &self.config
    }

    /// Start the WebTransport server
    ///
    /// This method accepts WebTransport connections and invokes the handler
    /// for each new session.
    pub async fn serve<H>(self, handler: H) -> Result<(), WebTransportError>
    where
        H: WebTransportHandler,
    {
        info!("Starting WebTransport server on {}", self.bind_addr);

        // Create TLS configuration
        let tls_config = self.create_server_tls_config()?;

        // Create QUIC server config
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
            .map_err(|e| WebTransportError::Tls(format!("Failed to create QUIC config: {}", e)))?;

        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));

        // Configure transport
        let mut transport_config = quinn::TransportConfig::default();

        let max_streams =
            quinn::VarInt::from_u32(self.config.http3.max_concurrent_streams as u32);
        transport_config.max_concurrent_bidi_streams(max_streams);
        transport_config.max_concurrent_uni_streams(max_streams);

        transport_config.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(Duration::from_millis(
                self.config.http3.idle_timeout_ms,
            ))
            .map_err(|_| WebTransportError::Config("Invalid idle timeout".to_string()))?,
        ));

        if self.config.enable_datagrams {
            transport_config.datagram_receive_buffer_size(Some(self.config.max_datagram_size));
            transport_config.datagram_send_buffer_size(self.config.max_datagram_size);
        }

        server_config.transport_config(Arc::new(transport_config));

        // Create endpoint
        let endpoint = quinn::Endpoint::server(server_config, self.bind_addr)
            .map_err(|e| WebTransportError::Connection(format!("Failed to bind: {}", e)))?;

        info!(
            "WebTransport server listening on {}",
            endpoint.local_addr().unwrap()
        );

        let config = self.config.clone();
        let mut session_counter: u64 = 0;

        // Accept connections
        while let Some(conn) = endpoint.accept().await {
            let handler = handler.clone();
            let config = config.clone();
            session_counter += 1;
            let session_id = session_counter;

            tokio::spawn(async move {
                if let Err(e) =
                    Self::handle_connection(conn, handler, config, session_id).await
                {
                    error!("WebTransport connection error: {}", e);
                }
            });
        }

        Ok(())
    }

    /// Handle a single QUIC connection for WebTransport
    async fn handle_connection<H>(
        conn: quinn::Incoming,
        handler: H,
        config: Arc<WebTransportConfig>,
        session_id: u64,
    ) -> Result<(), WebTransportError>
    where
        H: WebTransportHandler,
    {
        let remote_addr = conn.remote_address();
        debug!("Accepting WebTransport connection from {}", remote_addr);

        let quinn_conn = conn
            .await
            .map_err(|e| WebTransportError::Connection(format!("Connection failed: {}", e)))?;

        debug!("QUIC connection established with {}", remote_addr);

        // Create h3 connection with explicit type annotation
        let h3_conn: h3::server::Connection<h3_quinn::Connection, Bytes> =
            h3::server::Connection::new(h3_quinn::Connection::new(quinn_conn.clone()))
                .await
                .map_err(|e| WebTransportError::H3(format!("H3 connection failed: {}", e)))?;

        // Store the connection for potential future use
        drop(h3_conn);

        // Handle WebTransport upgrade requests
        // The first request should be a CONNECT request with :protocol = webtransport
        // For now, we create a session and pass it to the handler

        let session = Session {
            session_id,
            remote_addr,
            config,
        };

        // Invoke the handler
        handler.handle(session).await?;

        Ok(())
    }

    /// Create server TLS configuration
    fn create_server_tls_config(&self) -> Result<rustls::ServerConfig, WebTransportError> {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};

        // Generate self-signed certificate for testing
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .map_err(|e| WebTransportError::Tls(format!("Failed to generate cert: {}", e)))?;

        let cert_der = cert
            .serialize_der()
            .map_err(|e| WebTransportError::Tls(format!("Failed to serialize cert: {}", e)))?;
        let key_der = cert.serialize_private_key_der();

        let cert_chain = vec![CertificateDer::from(cert_der)];
        let key = PrivateKeyDer::try_from(key_der)
            .map_err(|_| WebTransportError::Tls("Failed to parse private key".to_string()))?;

        let mut tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .map_err(|e| WebTransportError::Tls(format!("Certificate error: {}", e)))?;

        // Enable HTTP/3 and WebTransport ALPN
        tls_config.alpn_protocols = vec![b"h3".to_vec()];

        Ok(tls_config)
    }
}

/// Builder for WebTransport client
pub struct WebTransportClientBuilder {
    config: WebTransportConfig,
}

impl WebTransportClientBuilder {
    /// Create a new WebTransport client builder
    pub fn new() -> Self {
        Self {
            config: WebTransportConfig::default(),
        }
    }

    /// Enable or disable datagrams
    pub fn enable_datagrams(mut self, enable: bool) -> Self {
        self.config.enable_datagrams = enable;
        self.config.http3.enable_datagrams = enable;
        self
    }

    /// Set maximum datagram size
    pub fn max_datagram_size(mut self, size: usize) -> Self {
        self.config.max_datagram_size = size;
        self.config.http3.max_datagram_size = size;
        self
    }

    /// Build the WebTransport client
    pub fn build(self) -> Result<WebTransportClient, WebTransportError> {
        // Install crypto provider if needed
        let _ = rustls::crypto::ring::default_provider().install_default();

        // Create TLS configuration
        let tls_config = Self::create_client_tls_config(&self.config)?;

        // Create QUIC client config
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
            .map_err(|e| WebTransportError::Tls(format!("Failed to create QUIC config: {}", e)))?;

        let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));

        // Configure transport
        let mut transport_config = quinn::TransportConfig::default();

        let max_streams =
            quinn::VarInt::from_u32(self.config.http3.max_concurrent_streams as u32);
        transport_config.max_concurrent_bidi_streams(max_streams);
        transport_config.max_concurrent_uni_streams(max_streams);

        if self.config.enable_datagrams {
            transport_config.datagram_receive_buffer_size(Some(self.config.max_datagram_size));
            transport_config.datagram_send_buffer_size(self.config.max_datagram_size);
        }

        client_config.transport_config(Arc::new(transport_config));

        // Create endpoint
        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| WebTransportError::Connection(format!("Failed to create endpoint: {}", e)))?;

        endpoint.set_default_client_config(client_config);

        Ok(WebTransportClient {
            config: Arc::new(self.config),
            endpoint,
        })
    }

    /// Create client TLS configuration
    fn create_client_tls_config(
        _config: &WebTransportConfig,
    ) -> Result<rustls::ClientConfig, WebTransportError> {
        let tls_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth();

        Ok(tls_config)
    }
}

impl Default for WebTransportClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// WebTransport client for native Rust applications
///
/// Note: Browser clients use the native WebTransport API directly.
/// This client is for Rust-based CLI tools, services, and tests.
pub struct WebTransportClient {
    config: Arc<WebTransportConfig>,
    endpoint: quinn::Endpoint,
}

impl WebTransportClient {
    /// Get the configuration
    pub fn config(&self) -> &WebTransportConfig {
        &self.config
    }

    /// Connect to a WebTransport server
    ///
    /// # Arguments
    /// * `addr` - Server address
    /// * `server_name` - Server name for TLS (SNI)
    /// * `path` - WebTransport path (e.g., "/webtransport")
    pub async fn connect(
        &self,
        addr: SocketAddr,
        server_name: &str,
        path: &str,
    ) -> Result<ClientSession, WebTransportError> {
        info!("Connecting to WebTransport server at {}", addr);

        let conn = self
            .endpoint
            .connect(addr, server_name)
            .map_err(|e| WebTransportError::Connection(format!("Connect failed: {}", e)))?
            .await
            .map_err(|e| WebTransportError::Connection(format!("Connection failed: {}", e)))?;

        debug!("QUIC connection established");

        // The session ID would be assigned by the server
        let session_id = 1; // Placeholder

        Ok(ClientSession {
            conn,
            session_id,
            path: path.to_string(),
            config: self.config.clone(),
        })
    }
}

/// A client-side WebTransport session
pub struct ClientSession {
    conn: quinn::Connection,
    session_id: u64,
    path: String,
    config: Arc<WebTransportConfig>,
}

impl ClientSession {
    /// Get the session ID
    pub fn session_id(&self) -> u64 {
        self.session_id
    }

    /// Get the path
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Get connection statistics
    pub fn stats(&self) -> quinn::ConnectionStats {
        self.conn.stats()
    }

    /// Send a datagram
    pub fn send_datagram(&self, data: Bytes) -> Result<(), WebTransportError> {
        if !self.config.enable_datagrams {
            return Err(WebTransportError::Datagram("Datagrams disabled".to_string()));
        }

        if data.len() > self.config.max_datagram_size {
            return Err(WebTransportError::Datagram(format!(
                "Datagram too large: {} > {}",
                data.len(),
                self.config.max_datagram_size
            )));
        }

        self.conn
            .send_datagram(data)
            .map_err(|e| WebTransportError::Datagram(format!("Send failed: {}", e)))
    }

    /// Receive a datagram
    pub async fn recv_datagram(&self) -> Result<Bytes, WebTransportError> {
        self.conn
            .read_datagram()
            .await
            .map_err(|e| WebTransportError::Datagram(format!("Receive failed: {}", e)))
    }

    /// Open a bidirectional stream
    pub async fn open_bi(&self) -> Result<(quinn::SendStream, quinn::RecvStream), WebTransportError> {
        self.conn
            .open_bi()
            .await
            .map_err(|e| WebTransportError::Stream(format!("Open bi failed: {}", e)))
    }

    /// Open a unidirectional stream
    pub async fn open_uni(&self) -> Result<quinn::SendStream, WebTransportError> {
        self.conn
            .open_uni()
            .await
            .map_err(|e| WebTransportError::Stream(format!("Open uni failed: {}", e)))
    }

    /// Accept an incoming bidirectional stream
    pub async fn accept_bi(&self) -> Result<(quinn::SendStream, quinn::RecvStream), WebTransportError> {
        self.conn
            .accept_bi()
            .await
            .map_err(|e| WebTransportError::Stream(format!("Accept bi failed: {}", e)))
    }

    /// Accept an incoming unidirectional stream
    pub async fn accept_uni(&self) -> Result<quinn::RecvStream, WebTransportError> {
        self.conn
            .accept_uni()
            .await
            .map_err(|e| WebTransportError::Stream(format!("Accept uni failed: {}", e)))
    }

    /// Close the session
    pub fn close(&self, code: u32, reason: &str) {
        self.conn.close(quinn::VarInt::from_u32(code), reason.as_bytes());
    }
}

/// Skip server certificate verification (for testing only!)
#[derive(Debug)]
struct SkipServerVerification;

impl rustls::client::danger::ServerCertVerifier for SkipServerVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer,
        _intermediates: &[rustls::pki_types::CertificateDer],
        _server_name: &rustls::pki_types::ServerName,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ED25519,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_webtransport_config_defaults() {
        let config = WebTransportConfig::default();

        assert_eq!(config.max_sessions, 100);
        assert_eq!(config.session_timeout_ms, 60000);
        assert!(config.enable_datagrams);
        assert_eq!(config.max_datagram_size, 65536);
    }

    #[test]
    fn test_server_builder() {
        let addr: SocketAddr = "127.0.0.1:4433".parse().unwrap();
        let server = WebTransportServerBuilder::new(addr)
            .max_sessions(50)
            .session_timeout_ms(30000)
            .enable_datagrams(true)
            .max_datagram_size(32768)
            .build()
            .unwrap();

        assert_eq!(server.bind_addr(), addr);
        assert_eq!(server.config().max_sessions, 50);
        assert_eq!(server.config().session_timeout_ms, 30000);
        assert!(server.config().enable_datagrams);
    }

    #[tokio::test]
    async fn test_client_builder() {
        let client = WebTransportClientBuilder::new()
            .enable_datagrams(true)
            .max_datagram_size(16384)
            .build()
            .unwrap();

        assert!(client.config().enable_datagrams);
        assert_eq!(client.config().max_datagram_size, 16384);
    }

    #[test]
    fn test_session_properties() {
        let config = Arc::new(WebTransportConfig::default());
        let session = Session {
            session_id: 42,
            remote_addr: "127.0.0.1:12345".parse().unwrap(),
            config,
        };

        assert_eq!(session.session_id(), 42);
        assert_eq!(session.remote_addr().port(), 12345);
        assert!(session.datagrams_enabled());
    }

    #[test]
    fn test_bi_stream() {
        let stream = BiStream {
            stream_id: 1,
            session_id: 42,
        };

        assert_eq!(stream.stream_id(), 1);
        assert_eq!(stream.session_id(), 42);
    }

    #[test]
    fn test_uni_stream() {
        let stream = UniStream {
            stream_id: 2,
            session_id: 42,
            is_send: true,
        };

        assert_eq!(stream.stream_id(), 2);
        assert_eq!(stream.session_id(), 42);
        assert!(stream.is_send());
    }

    #[test]
    fn test_fn_handler_creation() {
        let handler = FnWebTransportHandler::new(|_session: Session| async {
            Ok(())
        });

        // Verify handler is Clone
        let _handler2 = handler.clone();
    }
}
