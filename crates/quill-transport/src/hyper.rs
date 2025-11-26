//! Hyper profile (HTTP/3 over QUIC) transport implementation

#[cfg(feature = "http3")]
use bytes::Bytes;
#[cfg(feature = "http3")]
use http::{Request, Response, StatusCode};
#[cfg(feature = "http3")]
use quill_core::PrismProfile;
#[cfg(feature = "http3")]
use std::future::Future;
#[cfg(feature = "http3")]
use std::net::SocketAddr;
#[cfg(feature = "http3")]
use std::pin::Pin;
#[cfg(feature = "http3")]
use std::sync::Arc;
#[cfg(feature = "http3")]
use std::time::Duration;
#[cfg(feature = "http3")]
use thiserror::Error;
#[cfg(feature = "http3")]
use tracing::{debug, error, info};
#[cfg(feature = "http3")]
use h3::quic;

/// HTTP/3 transport for the Hyper profile
#[cfg(feature = "http3")]
pub struct HyperTransport {
    profile: PrismProfile,
    config: HyperConfig,
}

/// Configuration for HTTP/3 transport
#[cfg(feature = "http3")]
#[derive(Debug, Clone)]
pub struct HyperConfig {
    /// Enable 0-RTT for idempotent requests
    pub enable_zero_rtt: bool,
    /// Enable HTTP/3 datagrams
    pub enable_datagrams: bool,
    /// Enable connection migration
    pub enable_connection_migration: bool,
    /// Initial max concurrent streams
    pub max_concurrent_streams: u64,
    /// Max datagram size (bytes)
    pub max_datagram_size: usize,
    /// Keep-alive interval (milliseconds)
    pub keep_alive_interval_ms: u64,
    /// Idle timeout (milliseconds)
    pub idle_timeout_ms: u64,
}

#[cfg(feature = "http3")]
impl Default for HyperConfig {
    fn default() -> Self {
        Self {
            enable_zero_rtt: false, // Disabled by default for safety
            enable_datagrams: true,
            enable_connection_migration: true,
            max_concurrent_streams: 100,
            max_datagram_size: 65536,
            keep_alive_interval_ms: 30000,
            idle_timeout_ms: 60000,
        }
    }
}

#[cfg(feature = "http3")]
impl HyperTransport {
    /// Create a new Hyper transport with default configuration
    pub fn new() -> Self {
        Self {
            profile: PrismProfile::Hyper,
            config: HyperConfig::default(),
        }
    }

    /// Create a new Hyper transport with custom configuration
    pub fn with_config(config: HyperConfig) -> Self {
        Self {
            profile: PrismProfile::Hyper,
            config,
        }
    }

    /// Get the profile this transport implements
    pub fn profile(&self) -> PrismProfile {
        self.profile
    }

    /// Get the configuration
    pub fn config(&self) -> &HyperConfig {
        &self.config
    }

    /// Check if 0-RTT is enabled
    pub fn is_zero_rtt_enabled(&self) -> bool {
        self.config.enable_zero_rtt
    }

    /// Check if datagrams are enabled
    pub fn is_datagrams_enabled(&self) -> bool {
        self.config.enable_datagrams
    }
}

#[cfg(feature = "http3")]
impl Default for HyperTransport {
    fn default() -> Self {
        Self::new()
    }
}

/// HTTP/3 connection handler
#[cfg(feature = "http3")]
pub type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send>>;

/// HTTP/3 service trait for handling requests
#[cfg(feature = "http3")]
pub trait H3Service: Clone + Send + 'static {
    fn call(&self, req: Request<()>) -> BoxFuture<Result<Response<Bytes>, StatusCode>>;
}

/// HTTP/3 server builder
#[cfg(feature = "http3")]
pub struct H3ServerBuilder {
    config: HyperConfig,
    bind_addr: SocketAddr,
}

#[cfg(feature = "http3")]
impl H3ServerBuilder {
    /// Create a new HTTP/3 server builder
    pub fn new(bind_addr: SocketAddr) -> Self {
        Self {
            config: HyperConfig::default(),
            bind_addr,
        }
    }

    /// Enable 0-RTT
    pub fn enable_zero_rtt(mut self, enable: bool) -> Self {
        self.config.enable_zero_rtt = enable;
        self
    }

    /// Enable datagrams
    pub fn enable_datagrams(mut self, enable: bool) -> Self {
        self.config.enable_datagrams = enable;
        self
    }

    /// Set max concurrent streams
    pub fn max_concurrent_streams(mut self, max: u64) -> Self {
        self.config.max_concurrent_streams = max;
        self
    }

    /// Set idle timeout
    pub fn idle_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.config.idle_timeout_ms = timeout_ms;
        self
    }

    /// Build the HTTP/3 server
    pub fn build(self) -> Result<H3Server, HyperError> {
        Ok(H3Server {
            config: self.config,
            bind_addr: self.bind_addr,
            endpoint: None,
        })
    }
}

/// HTTP/3 server
#[cfg(feature = "http3")]
pub struct H3Server {
    config: HyperConfig,
    bind_addr: SocketAddr,
    endpoint: Option<quinn::Endpoint>,
}

#[cfg(feature = "http3")]
impl H3Server {
    /// Get the bind address
    pub fn bind_addr(&self) -> SocketAddr {
        self.bind_addr
    }

    /// Get the configuration
    pub fn config(&self) -> &HyperConfig {
        &self.config
    }

    /// Start the HTTP/3 server and accept connections
    ///
    /// # Arguments
    /// * `service` - The service to handle incoming requests
    pub async fn serve<S>(mut self, service: S) -> Result<(), HyperError>
    where
        S: H3Service,
    {
        info!("Starting HTTP/3 server on {}", self.bind_addr);

        // Create rustls server configuration
        let tls_config = self.create_server_tls_config()?;

        // Wrap in QuicServerConfig
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
            .map_err(|e| HyperError::Tls(format!("Failed to create QUIC server config: {}", e)))?;

        // Create quinn server configuration
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(crypto));

        // Configure transport
        let mut transport_config = quinn::TransportConfig::default();

        let max_streams = quinn::VarInt::from_u32(self.config.max_concurrent_streams as u32);
        transport_config.max_concurrent_bidi_streams(max_streams);
        transport_config.max_concurrent_uni_streams(max_streams);

        transport_config.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(Duration::from_millis(self.config.idle_timeout_ms))
                .map_err(|_| HyperError::Config("Invalid idle timeout".to_string()))?
        ));
        transport_config.keep_alive_interval(Some(Duration::from_millis(self.config.keep_alive_interval_ms)));

        if self.config.enable_datagrams {
            transport_config.datagram_receive_buffer_size(Some(self.config.max_datagram_size));
            transport_config.datagram_send_buffer_size(self.config.max_datagram_size);
        }

        server_config.transport_config(Arc::new(transport_config));

        // Create and bind endpoint
        let endpoint = quinn::Endpoint::server(server_config, self.bind_addr)
            .map_err(|e| HyperError::QuicConnection(format!("Failed to bind endpoint: {}", e)))?;

        info!("HTTP/3 server listening on {}", endpoint.local_addr().unwrap());
        self.endpoint = Some(endpoint.clone());

        // Accept connections
        while let Some(conn) = endpoint.accept().await {
            let service = service.clone();
            let config = self.config.clone();

            tokio::spawn(async move {
                if let Err(e) = Self::handle_connection(conn, service, config).await {
                    error!("Connection error: {}", e);
                }
            });
        }

        Ok(())
    }

    /// Handle a single QUIC connection
    async fn handle_connection<S>(
        conn: quinn::Incoming,
        service: S,
        _config: HyperConfig,
    ) -> Result<(), HyperError>
    where
        S: H3Service,
    {
        let remote_addr = conn.remote_address();
        debug!("Accepting connection from {}", remote_addr);

        let quinn_conn = conn
            .await
            .map_err(|e| HyperError::QuicConnection(format!("Connection failed: {}", e)))?;

        debug!("Connection established with {}", remote_addr);

        // Create h3 connection
        let mut h3_conn = h3::server::Connection::new(h3_quinn::Connection::new(quinn_conn))
            .await
            .map_err(|e| HyperError::H3Stream(format!("H3 connection failed: {}", e)))?;

        // Handle requests
        loop {
            match h3_conn.accept().await {
                Ok(Some(resolver)) => {
                    let service = service.clone();
                    tokio::spawn(async move {
                        // Resolve the request headers
                        match resolver.resolve_request().await {
                            Ok((req, stream)) => {
                                if let Err(e) = Self::handle_request(req, stream, service).await {
                                    error!("Request error: {}", e);
                                }
                            }
                            Err(e) => {
                                error!("Failed to resolve request: {}", e);
                            }
                        }
                    });
                }
                Ok(None) => {
                    debug!("Connection closed by client");
                    break;
                }
                Err(e) => {
                    error!("Error accepting request: {}", e);
                    break;
                }
            }
        }

        Ok(())
    }

    /// Handle a single HTTP/3 request
    async fn handle_request<S, B>(
        req: Request<()>,
        mut stream: h3::server::RequestStream<B, Bytes>,
        service: S,
    ) -> Result<(), HyperError>
    where
        S: H3Service,
        B: quic::BidiStream<Bytes>,
    {
        debug!("Handling request: {} {}", req.method(), req.uri());

        // Call the service
        let response = service.call(req).await;

        // Send response
        match response {
            Ok(resp) => {
                let (parts, body) = resp.into_parts();
                let resp = Response::from_parts(parts, ());

                stream
                    .send_response(resp)
                    .await
                    .map_err(|e| HyperError::H3Stream(format!("Failed to send response: {}", e)))?;

                stream
                    .send_data(body)
                    .await
                    .map_err(|e| HyperError::H3Stream(format!("Failed to send body: {}", e)))?;

                stream
                    .finish()
                    .await
                    .map_err(|e| HyperError::H3Stream(format!("Failed to finish stream: {}", e)))?;

                debug!("Response sent successfully");
            }
            Err(status) => {
                let resp = Response::builder()
                    .status(status)
                    .body(())
                    .unwrap();

                stream
                    .send_response(resp)
                    .await
                    .map_err(|e| HyperError::H3Stream(format!("Failed to send error response: {}", e)))?;

                stream
                    .finish()
                    .await
                    .map_err(|e| HyperError::H3Stream(format!("Failed to finish stream: {}", e)))?;
            }
        }

        Ok(())
    }

    /// Create server TLS configuration
    fn create_server_tls_config(&self) -> Result<rustls::ServerConfig, HyperError> {
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};

        // TODO: Load certificates from configuration
        // For now, create a self-signed certificate for testing
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .map_err(|e| HyperError::Tls(format!("Failed to generate certificate: {}", e)))?;

        let cert_der = cert.serialize_der()
            .map_err(|e| HyperError::Tls(format!("Failed to serialize certificate: {}", e)))?;
        let key_der = cert.serialize_private_key_der();

        let cert_chain = vec![CertificateDer::from(cert_der)];
        let key = PrivateKeyDer::try_from(key_der)
            .map_err(|_| HyperError::Tls("Failed to parse private key".to_string()))?;

        let mut tls_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(cert_chain, key)
            .map_err(|e| HyperError::Tls(format!("Certificate error: {}", e)))?;

        tls_config.alpn_protocols = vec![b"h3".to_vec()];
        // Note: 0-RTT is controlled at the QUIC layer via max_early_data_size

        Ok(tls_config)
    }
}

/// HTTP/3 client builder
#[cfg(feature = "http3")]
pub struct H3ClientBuilder {
    config: HyperConfig,
}

#[cfg(feature = "http3")]
impl H3ClientBuilder {
    /// Create a new HTTP/3 client builder
    pub fn new() -> Self {
        Self {
            config: HyperConfig::default(),
        }
    }

    /// Enable 0-RTT for idempotent requests
    pub fn enable_zero_rtt(mut self, enable: bool) -> Self {
        self.config.enable_zero_rtt = enable;
        self
    }

    /// Enable datagrams
    pub fn enable_datagrams(mut self, enable: bool) -> Self {
        self.config.enable_datagrams = enable;
        self
    }

    /// Build the HTTP/3 client
    pub fn build(self) -> Result<H3Client, HyperError> {
        H3Client::new(self.config)
    }
}

#[cfg(feature = "http3")]
impl Default for H3ClientBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// HTTP/3 client
#[cfg(feature = "http3")]
pub struct H3Client {
    config: Arc<HyperConfig>,
    endpoint: quinn::Endpoint,
}

#[cfg(feature = "http3")]
impl H3Client {
    /// Get the configuration
    pub fn config(&self) -> &HyperConfig {
        &self.config
    }

    /// Create a new H3Client with endpoint
    pub fn new(config: HyperConfig) -> Result<Self, HyperError> {
        // Create client TLS configuration
        let tls_config = Self::create_client_tls_config(&config)?;

        // Wrap in QuicClientConfig
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls_config)
            .map_err(|e| HyperError::Tls(format!("Failed to create QUIC client config: {}", e)))?;

        // Create quinn client configuration
        let mut client_config = quinn::ClientConfig::new(Arc::new(crypto));

        // Configure transport
        let mut transport_config = quinn::TransportConfig::default();

        let max_streams = quinn::VarInt::from_u32(config.max_concurrent_streams as u32);
        transport_config.max_concurrent_bidi_streams(max_streams);
        transport_config.max_concurrent_uni_streams(max_streams);

        transport_config.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(Duration::from_millis(config.idle_timeout_ms))
                .map_err(|_| HyperError::Config("Invalid idle timeout".to_string()))?
        ));
        transport_config.keep_alive_interval(Some(Duration::from_millis(config.keep_alive_interval_ms)));

        if config.enable_datagrams {
            transport_config.datagram_receive_buffer_size(Some(config.max_datagram_size));
            transport_config.datagram_send_buffer_size(config.max_datagram_size);
        }

        client_config.transport_config(Arc::new(transport_config));

        // Create endpoint
        let mut endpoint = quinn::Endpoint::client("0.0.0.0:0".parse().unwrap())
            .map_err(|e| HyperError::QuicConnection(format!("Failed to create endpoint: {}", e)))?;

        endpoint.set_default_client_config(client_config);

        Ok(Self {
            config: Arc::new(config),
            endpoint,
        })
    }

    /// Send an HTTP/3 request
    ///
    /// # Arguments
    /// * `addr` - The server address to connect to
    /// * `req` - The HTTP request to send (body as Bytes)
    ///
    /// # Returns
    /// The HTTP response with body as Bytes
    pub async fn send_request(
        &self,
        addr: SocketAddr,
        req: Request<Bytes>,
    ) -> Result<Response<Bytes>, HyperError> {
        info!("Connecting to {}", addr);

        // Connect to server
        let conn = self
            .endpoint
            .connect(addr, "localhost")
            .map_err(|e| HyperError::QuicConnection(format!("Connection failed: {}", e)))?
            .await
            .map_err(|e| HyperError::QuicConnection(format!("Connection failed: {}", e)))?;

        debug!("QUIC connection established");

        // Create h3 connection
        let quinn_conn = h3_quinn::Connection::new(conn);
        let (mut driver, mut send_request) = h3::client::new(quinn_conn)
            .await
            .map_err(|e| HyperError::H3Stream(format!("H3 connection failed: {}", e)))?;

        // Spawn driver task
        tokio::spawn(async move {
            // drive() runs the connection until it completes
            futures::future::poll_fn(|cx| driver.poll_close(cx)).await;
        });

        // Convert request
        let (parts, body) = req.into_parts();
        let req = Request::from_parts(parts, ());

        // Send request
        let mut stream = send_request
            .send_request(req)
            .await
            .map_err(|e| HyperError::H3Stream(format!("Failed to send request: {}", e)))?;

        // Send body
        stream
            .send_data(body)
            .await
            .map_err(|e| HyperError::H3Stream(format!("Failed to send body: {}", e)))?;

        stream
            .finish()
            .await
            .map_err(|e| HyperError::H3Stream(format!("Failed to finish request: {}", e)))?;

        debug!("Request sent, waiting for response");

        // Receive response
        let resp = stream
            .recv_response()
            .await
            .map_err(|e| HyperError::H3Stream(format!("Failed to receive response: {}", e)))?;

        // Read body
        let mut body_data = Vec::new();
        while let Some(mut chunk) = stream
            .recv_data()
            .await
            .map_err(|e| HyperError::H3Stream(format!("Failed to receive body: {}", e)))?
        {
            use bytes::Buf;
            body_data.extend_from_slice(chunk.chunk());
            chunk.advance(chunk.remaining());
        }

        debug!("Response received: {} bytes", body_data.len());

        Ok(resp.map(|_| Bytes::from(body_data)))
    }

    /// Create client TLS configuration
    fn create_client_tls_config(config: &HyperConfig) -> Result<rustls::ClientConfig, HyperError> {
        let mut tls_config = rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification))
            .with_no_client_auth();

        tls_config.alpn_protocols = vec![b"h3".to_vec()];
        tls_config.enable_early_data = config.enable_zero_rtt;

        Ok(tls_config)
    }
}

/// Skip server certificate verification (for testing only!)
#[cfg(feature = "http3")]
#[derive(Debug)]
struct SkipServerVerification;

#[cfg(feature = "http3")]
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

/// HTTP/3 transport errors
#[cfg(feature = "http3")]
#[derive(Debug, Error)]
pub enum HyperError {
    #[error("QUIC connection error: {0}")]
    QuicConnection(String),

    #[error("HTTP/3 stream error: {0}")]
    H3Stream(String),

    #[error("0-RTT rejected: {0}")]
    ZeroRttRejected(String),

    #[error("Datagram error: {0}")]
    Datagram(String),

    #[error("TLS error: {0}")]
    Tls(String),

    #[error("Configuration error: {0}")]
    Config(String),
}

// Stub implementations when http3 feature is disabled
#[cfg(not(feature = "http3"))]
pub struct HyperTransport;

#[cfg(not(feature = "http3"))]
impl HyperTransport {
    pub fn new() -> Self {
        panic!("HTTP/3 support requires the 'http3' feature to be enabled");
    }
}

#[cfg(test)]
#[cfg(feature = "http3")]
mod tests {
    use super::*;

    #[test]
    fn test_hyper_transport() {
        let transport = HyperTransport::new();
        assert_eq!(transport.profile(), PrismProfile::Hyper);
        assert!(!transport.is_zero_rtt_enabled()); // Disabled by default
        assert!(transport.is_datagrams_enabled()); // Enabled by default
    }

    #[test]
    fn test_hyper_config() {
        let config = HyperConfig {
            enable_zero_rtt: true,
            enable_datagrams: true,
            enable_connection_migration: true,
            max_concurrent_streams: 200,
            max_datagram_size: 32768,
            keep_alive_interval_ms: 15000,
            idle_timeout_ms: 30000,
        };

        let transport = HyperTransport::with_config(config);
        assert!(transport.is_zero_rtt_enabled());
        assert_eq!(transport.config().max_concurrent_streams, 200);
    }

    #[test]
    fn test_server_builder() {
        let addr = "127.0.0.1:4433".parse().unwrap();
        let server = H3ServerBuilder::new(addr)
            .enable_zero_rtt(true)
            .enable_datagrams(true)
            .max_concurrent_streams(150)
            .idle_timeout_ms(45000)
            .build()
            .unwrap();

        assert_eq!(server.bind_addr(), addr);
        assert!(server.config().enable_zero_rtt);
        assert_eq!(server.config().max_concurrent_streams, 150);
    }

    #[tokio::test]
    async fn test_client_builder() {
        // Install the ring crypto provider for rustls
        let _ = rustls::crypto::ring::default_provider().install_default();

        let client = H3ClientBuilder::new()
            .enable_zero_rtt(true)
            .enable_datagrams(false)
            .build()
            .unwrap();

        assert!(client.config().enable_zero_rtt);
        assert!(!client.config().enable_datagrams);
    }
}
