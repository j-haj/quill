//! Server SDK for the Quill RPC framework.
//!
//! This crate provides server-side components:
//! - HTTP router for RPC methods
//! - Handler traits
//! - Middleware (Problem Details, compression, tracing)
//! - Server runtime
//! - Streaming support
//! - HTTP/3 support (with `http3` feature)

#[cfg(feature = "http3")]
pub mod h3_server;
pub mod handler;
pub mod middleware;
pub mod observability;
pub mod request_stream;
pub mod router;
pub mod security;
pub mod server;
pub mod streaming;

#[cfg(feature = "http3")]
pub use h3_server::{H3ServerBuilder, H3ServerConfig, QuillH3Server};
pub use handler::RpcHandler;
pub use observability::{check_dependency, DependencyStatus, HealthStatus, ObservabilityCollector};
pub use request_stream::RequestFrameStream;
pub use router::{parse_rpc_path, RpcRouter};
pub use security::{
    is_early_data_request, CompressionExclusions, IdempotencyChecker, EARLY_DATA_HEADER,
    STATUS_TOO_EARLY,
};
pub use server::{HttpVersion, QuillServer, ServerBuilder, ServerConfig};
pub use streaming::{FramedResponseStream, RpcResponse};
