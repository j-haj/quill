//! gRPC to Quill Bridge Example
//!
//! This example demonstrates how to use the gRPC bridge to enable interoperability
//! between gRPC clients and Quill services.
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────┐         ┌─────────────┐         ┌──────────────┐
//! │ gRPC Client │────────▶│ gRPC Bridge │────────▶│ Quill Server │
//! └─────────────┘         └─────────────┘         └──────────────┘
//! ```
//!
//! ## Features Demonstrated
//!
//! - Unary RPC bridging (gRPC → Quill)
//! - Status code translation
//! - Metadata/header forwarding
//! - Error handling with Problem Details
//!
//! ## Running the Example
//!
//! ```bash
//! cargo test -p grpc-bridge-example
//! ```

use bytes::Bytes;
use prost::Message;
use quill_core::QuillError;

// Include generated protobuf code (tonic)
pub mod echo {
    pub mod v1 {
        tonic::include_proto!("echo.v1");
    }
}

pub use echo::v1::{EchoRequest, EchoResponse};
pub use echo::v1::echo_service_server::{EchoService, EchoServiceServer};
pub use echo::v1::echo_service_client::EchoServiceClient;

/// Quill-style handler for echo requests
///
/// This handler can be used with QuillServer to handle echo requests
/// from bridged gRPC clients.
pub async fn handle_echo(request: Bytes) -> Result<Bytes, QuillError> {
    // Decode the protobuf request
    let req = EchoRequest::decode(request)
        .map_err(|e| QuillError::Rpc(format!("Failed to decode request: {}", e)))?;

    tracing::info!("Quill server received echo: {}", req.message);

    // Create response (echo back the message)
    let resp = EchoResponse {
        message: req.message,
    };

    // Encode the response
    let mut buf = Vec::new();
    resp.encode(&mut buf)
        .map_err(|e| QuillError::Rpc(format!("Failed to encode response: {}", e)))?;

    Ok(Bytes::from(buf))
}

/// gRPC service implementation that bridges to Quill
///
/// This service implements the tonic EchoService trait and bridges
/// all calls to a Quill backend using the GrpcBridge.
pub struct EchoServiceBridge {
    bridge: quill_grpc_bridge::GrpcBridge,
}

impl EchoServiceBridge {
    /// Create a new bridge service
    pub fn new(quill_base_url: &str) -> Result<Self, String> {
        let config = quill_grpc_bridge::GrpcBridgeConfig {
            quill_base_url: quill_base_url.to_string(),
            enable_logging: true,
            forward_metadata: true,
        };

        let bridge = quill_grpc_bridge::GrpcBridge::new(config)?;

        Ok(Self { bridge })
    }
}

#[tonic::async_trait]
impl EchoService for EchoServiceBridge {
    async fn echo(
        &self,
        request: tonic::Request<EchoRequest>,
    ) -> Result<tonic::Response<EchoResponse>, tonic::Status> {
        // Bridge the gRPC call to Quill
        self.bridge
            .call_unary("echo.v1.EchoService", "Echo", request)
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use quill_grpc_bridge::{GrpcBridge, GrpcBridgeConfig};
    use tonic::Code;

    #[test]
    fn test_handle_echo() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let request = EchoRequest {
                message: "Hello, Bridge!".to_string(),
            };

            let mut buf = Vec::new();
            request.encode(&mut buf).unwrap();

            let response_bytes = handle_echo(Bytes::from(buf)).await.unwrap();
            let response = EchoResponse::decode(&response_bytes[..]).unwrap();

            assert_eq!(response.message, "Hello, Bridge!");
        });
    }

    #[test]
    fn test_handle_echo_empty_message() {
        let rt = tokio::runtime::Runtime::new().unwrap();
        rt.block_on(async {
            let request = EchoRequest {
                message: String::new(),
            };

            let mut buf = Vec::new();
            request.encode(&mut buf).unwrap();

            let response_bytes = handle_echo(Bytes::from(buf)).await.unwrap();
            let response = EchoResponse::decode(&response_bytes[..]).unwrap();

            assert_eq!(response.message, "");
        });
    }

    #[test]
    fn test_bridge_config() {
        let config = GrpcBridgeConfig {
            quill_base_url: "http://localhost:8080".to_string(),
            enable_logging: true,
            forward_metadata: true,
        };

        let bridge = GrpcBridge::new(config);
        assert!(bridge.is_ok());
    }

    #[test]
    fn test_echo_service_bridge_creation() {
        let bridge = EchoServiceBridge::new("http://localhost:8080");
        assert!(bridge.is_ok());
    }

    #[test]
    fn test_status_code_mapping() {
        use quill_grpc_bridge::{grpc_to_http_status, http_to_grpc_status};
        use http::StatusCode;

        // Test gRPC to HTTP
        assert_eq!(grpc_to_http_status(Code::Ok), StatusCode::OK);
        assert_eq!(grpc_to_http_status(Code::NotFound), StatusCode::NOT_FOUND);
        assert_eq!(grpc_to_http_status(Code::InvalidArgument), StatusCode::BAD_REQUEST);
        assert_eq!(grpc_to_http_status(Code::Unauthenticated), StatusCode::UNAUTHORIZED);
        assert_eq!(grpc_to_http_status(Code::PermissionDenied), StatusCode::FORBIDDEN);
        assert_eq!(grpc_to_http_status(Code::ResourceExhausted), StatusCode::TOO_MANY_REQUESTS);

        // Test HTTP to gRPC
        assert_eq!(http_to_grpc_status(StatusCode::OK), Code::Ok);
        assert_eq!(http_to_grpc_status(StatusCode::NOT_FOUND), Code::NotFound);
        assert_eq!(http_to_grpc_status(StatusCode::BAD_REQUEST), Code::InvalidArgument);
        assert_eq!(http_to_grpc_status(StatusCode::UNAUTHORIZED), Code::Unauthenticated);
        assert_eq!(http_to_grpc_status(StatusCode::FORBIDDEN), Code::PermissionDenied);
    }

    #[test]
    fn test_problem_details_conversion() {
        use quill_grpc_bridge::grpc_to_problem_details;

        let details = grpc_to_problem_details(Code::NotFound, "User not found".to_string());

        assert_eq!(details.status, 404);
        assert_eq!(details.title, "Not Found");
        assert_eq!(details.type_uri, "urn:grpc:status:NOT_FOUND");
        assert!(details.detail.unwrap().contains("User not found"));
    }

    #[test]
    fn test_metadata_translation() {
        use quill_grpc_bridge::{grpc_metadata_to_http_headers, http_headers_to_grpc_metadata};
        use tonic::metadata::MetadataMap;
        use http::HeaderMap;

        // Test gRPC to HTTP
        let mut grpc_metadata = MetadataMap::new();
        grpc_metadata.insert("authorization", "Bearer token123".parse().unwrap());
        grpc_metadata.insert("x-custom-header", "custom-value".parse().unwrap());

        let http_headers = grpc_metadata_to_http_headers(&grpc_metadata);
        assert!(http_headers.contains_key("authorization"));
        assert!(http_headers.contains_key("x-custom-header"));

        // Test HTTP to gRPC
        let mut http_headers = HeaderMap::new();
        http_headers.insert(http::header::AUTHORIZATION, "Bearer token456".parse().unwrap());

        let grpc_metadata = http_headers_to_grpc_metadata(&http_headers);
        assert!(grpc_metadata.get("authorization").is_some());
    }

    #[test]
    fn test_binary_metadata_encoding() {
        use quill_grpc_bridge::grpc_metadata_to_http_headers;
        use tonic::metadata::MetadataMap;

        let mut grpc_metadata = MetadataMap::new();
        // Binary metadata keys end in "-bin"
        grpc_metadata.insert_bin(
            "trace-id-bin",
            tonic::metadata::MetadataValue::from_bytes(&[0x01, 0x02, 0x03, 0x04]),
        );

        let http_headers = grpc_metadata_to_http_headers(&grpc_metadata);
        // Binary values should be base64 encoded
        if let Some(value) = http_headers.get("trace-id-bin") {
            let value_str = value.to_str().unwrap();
            // Should be base64 encoded
            assert!(base64_simd::STANDARD.decode_to_vec(value_str).is_ok());
        }
    }

    #[test]
    fn test_grpc_internal_headers_filtered() {
        use quill_grpc_bridge::grpc_metadata_to_http_headers;
        use tonic::metadata::MetadataMap;

        let mut grpc_metadata = MetadataMap::new();
        grpc_metadata.insert("grpc-timeout", "10S".parse().unwrap());
        grpc_metadata.insert("x-custom", "value".parse().unwrap());

        let http_headers = grpc_metadata_to_http_headers(&grpc_metadata);

        // grpc-timeout should be filtered out
        assert!(!http_headers.contains_key("grpc-timeout"));
        // custom header should be preserved
        assert!(http_headers.contains_key("x-custom"));
    }
}
