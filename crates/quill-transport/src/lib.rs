//! Transport layer implementations for Quill RPC.
//!
//! This crate provides the transport layer for different Prism profiles:
//! - Classic: HTTP/1.1 and basic HTTP/2
//! - Turbo: Full HTTP/2
//! - Hyper: HTTP/3 over QUIC
//! - WebTransport: Browser-compatible HTTP/3 with streams and datagrams

pub mod classic;
pub mod hyper;
pub mod negotiation;
pub mod turbo;

#[cfg(feature = "webtransport")]
pub mod webtransport;

pub use classic::ClassicTransport;
pub use negotiation::{negotiate_profile, ProfileNegotiator};
pub use turbo::TurboTransport;

#[cfg(feature = "http3")]
pub use hyper::{
    BoxFuture, Datagram, DatagramHandler, DatagramReceiver, DatagramSender, FnDatagramHandler,
    H3Client, H3ClientBuilder, H3Connection, H3Server, H3ServerBuilder, H3Service, HyperConfig,
    HyperError, HyperTransport, ServerConnection,
};

#[cfg(feature = "webtransport")]
pub use webtransport::{
    BiStream, ClientSession, FnWebTransportHandler, Session, UniStream, WebTransportClient,
    WebTransportClientBuilder, WebTransportConfig, WebTransportError, WebTransportHandler,
    WebTransportServer, WebTransportServerBuilder,
};
