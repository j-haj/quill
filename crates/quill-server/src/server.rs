//! Quill server implementation

use crate::router::{RequestStream, RpcRouter};
use crate::streaming::RpcResponse;
use bytes::Bytes;
use http::Request;
use hyper::body::Incoming;
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto;
use quill_core::QuillError;
use std::future::Future;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::TcpListener;
use tracing::{error, info};

/// HTTP version configuration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpVersion {
    /// Automatically negotiate HTTP/1.1 or HTTP/2
    Auto,
    /// HTTP/1.1 only
    Http1Only,
    /// HTTP/2 only
    Http2Only,
}

/// Server configuration
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// HTTP version to use
    pub http_version: HttpVersion,
    /// HTTP/2 initial connection window size (bytes)
    pub http2_initial_connection_window_size: Option<u32>,
    /// HTTP/2 initial stream window size (bytes)
    pub http2_initial_stream_window_size: Option<u32>,
    /// HTTP/2 max concurrent streams
    pub http2_max_concurrent_streams: Option<u32>,
    /// HTTP/2 keep alive interval
    pub http2_keep_alive_interval: Option<Duration>,
    /// HTTP/2 keep alive timeout
    pub http2_keep_alive_timeout: Option<Duration>,
    /// HTTP/2 max frame size
    pub http2_max_frame_size: Option<u32>,
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            http_version: HttpVersion::Auto,
            http2_initial_connection_window_size: Some(1024 * 1024), // 1MB
            http2_initial_stream_window_size: Some(1024 * 1024),     // 1MB
            http2_max_concurrent_streams: Some(100),
            http2_keep_alive_interval: Some(Duration::from_secs(10)),
            http2_keep_alive_timeout: Some(Duration::from_secs(20)),
            http2_max_frame_size: Some(16 * 1024), // 16KB
        }
    }
}

/// Quill RPC server
pub struct QuillServer {
    router: Arc<RpcRouter>,
    config: ServerConfig,
}

impl QuillServer {
    /// Create a new server with a router
    pub fn new(router: RpcRouter) -> Self {
        Self {
            router: Arc::new(router),
            config: ServerConfig::default(),
        }
    }

    /// Create a new server with a router and custom configuration
    pub fn with_config(router: RpcRouter, config: ServerConfig) -> Self {
        Self {
            router: Arc::new(router),
            config,
        }
    }

    /// Create a builder for configuring the server
    pub fn builder() -> ServerBuilder {
        ServerBuilder::new()
    }

    /// Serve the server on the given address
    pub async fn serve(self, addr: SocketAddr) -> Result<(), Box<dyn std::error::Error>> {
        let listener = TcpListener::bind(addr).await?;
        info!(
            "Quill server listening on {} (HTTP version: {:?})",
            addr, self.config.http_version
        );

        let config = Arc::new(self.config);

        loop {
            let (stream, remote_addr) = listener.accept().await?;
            let router = Arc::clone(&self.router);
            let config = Arc::clone(&config);

            tokio::spawn(async move {
                let io = TokioIo::new(stream);

                let service = hyper::service::service_fn(move |req: Request<Incoming>| {
                    let router = Arc::clone(&router);
                    async move { Ok::<_, hyper::Error>(router.route(req).await) }
                });

                // Configure connection based on HTTP version setting
                let result: Result<(), Box<dyn std::error::Error + Send + Sync>> = match config.http_version {
                    HttpVersion::Http1Only => {
                        // HTTP/1.1 only
                        let mut builder = auto::Builder::new(TokioExecutor::new());
                        // Disable HTTP/2, keep HTTP/1
                        builder.http1();
                        builder.serve_connection(io, service).await.map_err(Into::into)
                    }
                    HttpVersion::Http2Only => {
                        // HTTP/2 only - use direct h2 module
                        use hyper::server::conn::http2;
                        let mut builder = http2::Builder::new(TokioExecutor::new());

                        if let Some(window_size) = config.http2_initial_connection_window_size {
                            builder.initial_connection_window_size(window_size);
                        }
                        if let Some(window_size) = config.http2_initial_stream_window_size {
                            builder.initial_stream_window_size(window_size);
                        }
                        if let Some(max_streams) = config.http2_max_concurrent_streams {
                            builder.max_concurrent_streams(max_streams);
                        }
                        if let Some(interval) = config.http2_keep_alive_interval {
                            builder.keep_alive_interval(interval);
                        }
                        if let Some(timeout) = config.http2_keep_alive_timeout {
                            builder.keep_alive_timeout(timeout);
                        }
                        if let Some(frame_size) = config.http2_max_frame_size {
                            builder.max_frame_size(frame_size);
                        }

                        builder.serve_connection(io, service).await.map_err(Into::into)
                    }
                    HttpVersion::Auto => {
                        // Auto-negotiate HTTP/1.1 or HTTP/2
                        let mut builder = auto::Builder::new(TokioExecutor::new());

                        // Configure HTTP/2 settings for when HTTP/2 is negotiated
                        let mut http2 = builder.http2();
                        if let Some(window_size) = config.http2_initial_connection_window_size {
                            http2.initial_connection_window_size(window_size);
                        }
                        if let Some(window_size) = config.http2_initial_stream_window_size {
                            http2.initial_stream_window_size(window_size);
                        }
                        if let Some(max_streams) = config.http2_max_concurrent_streams {
                            http2.max_concurrent_streams(max_streams);
                        }
                        if let Some(interval) = config.http2_keep_alive_interval {
                            http2.keep_alive_interval(interval);
                        }
                        if let Some(timeout) = config.http2_keep_alive_timeout {
                            http2.keep_alive_timeout(timeout);
                        }
                        if let Some(frame_size) = config.http2_max_frame_size {
                            http2.max_frame_size(frame_size);
                        }
                        drop(http2);

                        builder.serve_connection(io, service).await.map_err(Into::into)
                    }
                };

                if let Err(err) = result {
                    error!("Error serving connection from {}: {:?}", remote_addr, err);
                }
            });
        }
    }
}

/// Builder for creating a Quill server
pub struct ServerBuilder {
    router: RpcRouter,
    config: ServerConfig,
}

impl ServerBuilder {
    /// Create a new server builder
    pub fn new() -> Self {
        Self {
            router: RpcRouter::new(),
            config: ServerConfig::default(),
        }
    }

    /// Set the HTTP version
    pub fn http_version(mut self, version: HttpVersion) -> Self {
        self.config.http_version = version;
        self
    }

    /// Set HTTP/2 initial connection window size
    pub fn http2_initial_connection_window_size(mut self, size: u32) -> Self {
        self.config.http2_initial_connection_window_size = Some(size);
        self
    }

    /// Set HTTP/2 initial stream window size
    pub fn http2_initial_stream_window_size(mut self, size: u32) -> Self {
        self.config.http2_initial_stream_window_size = Some(size);
        self
    }

    /// Set HTTP/2 max concurrent streams
    pub fn http2_max_concurrent_streams(mut self, max: u32) -> Self {
        self.config.http2_max_concurrent_streams = Some(max);
        self
    }

    /// Set HTTP/2 keep alive interval
    pub fn http2_keep_alive_interval(mut self, interval: Duration) -> Self {
        self.config.http2_keep_alive_interval = Some(interval);
        self
    }

    /// Set HTTP/2 keep alive timeout
    pub fn http2_keep_alive_timeout(mut self, timeout: Duration) -> Self {
        self.config.http2_keep_alive_timeout = Some(timeout);
        self
    }

    /// Set HTTP/2 max frame size
    pub fn http2_max_frame_size(mut self, size: u32) -> Self {
        self.config.http2_max_frame_size = Some(size);
        self
    }

    /// Enable HTTP/2 only mode (Turbo profile)
    pub fn turbo_profile(self) -> Self {
        self.http_version(HttpVersion::Http2Only)
    }

    /// Register a unary handler for an RPC method
    /// Path format: "{package}.{Service}/{Method}"
    pub fn register<F, Fut>(mut self, path: impl Into<String>, handler: F) -> Self
    where
        F: Fn(Bytes) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Bytes, QuillError>> + Send + 'static,
    {
        self.router.register_unary(path, handler);
        self
    }

    /// Register a streaming handler for an RPC method (server streaming)
    /// Path format: "{package}.{Service}/{Method}"
    pub fn register_streaming<F, Fut>(mut self, path: impl Into<String>, handler: F) -> Self
    where
        F: Fn(Bytes) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<RpcResponse, QuillError>> + Send + 'static,
    {
        self.router.register(path, handler);
        self
    }

    /// Register a client streaming handler
    ///
    /// The handler receives a stream of request messages and returns a single response.
    /// Path format: "{package}.{Service}/{Method}"
    pub fn register_client_streaming<F, Fut>(mut self, path: impl Into<String>, handler: F) -> Self
    where
        F: Fn(RequestStream) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<RpcResponse, QuillError>> + Send + 'static,
    {
        self.router.register_client_streaming(path, handler);
        self
    }

    /// Register a bidirectional streaming handler
    ///
    /// The handler receives a stream of request messages and returns a stream of responses.
    /// Path format: "{package}.{Service}/{Method}"
    pub fn register_bidi_streaming<F, Fut>(mut self, path: impl Into<String>, handler: F) -> Self
    where
        F: Fn(RequestStream) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<RpcResponse, QuillError>> + Send + 'static,
    {
        self.router.register_bidi_streaming(path, handler);
        self
    }

    /// Build the server
    pub fn build(self) -> QuillServer {
        QuillServer::with_config(self.router, self.config)
    }
}

impl Default for ServerBuilder {
    fn default() -> Self {
        Self::new()
    }
}
