//! gRPC to Quill protocol bridge
//!
//! This crate provides bidirectional bridging between gRPC and Quill protocols,
//! enabling interoperability with existing gRPC services.
//!
//! # Features
//!
//! - gRPC status code to HTTP status / Problem Details mapping
//! - Metadata to HTTP header translation
//! - All streaming modes supported (unary, server, client, bidirectional)
//! - Transparent protobuf message passing
//! - Tracing and observability integration

pub mod status;
pub mod metadata;
pub mod bridge;

pub use status::{grpc_to_http_status, grpc_to_problem_details};
pub use metadata::{grpc_metadata_to_http_headers, http_headers_to_grpc_metadata};
pub use bridge::{GrpcBridge, GrpcBridgeConfig};
