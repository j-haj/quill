//! gRPC to Quill bridge implementation

use crate::status::{grpc_to_problem_details, problem_details_to_grpc_status};
use bytes::Bytes;
use quill_client::QuillClient;
use std::sync::Arc;
use tonic::{Request, Response, Status};
use tracing::info;

/// Configuration for the gRPC bridge
#[derive(Debug, Clone)]
pub struct GrpcBridgeConfig {
    /// Quill service base URL
    pub quill_base_url: String,
    /// Enable request/response logging
    pub enable_logging: bool,
    /// Forward all metadata/headers
    pub forward_metadata: bool,
}

impl Default for GrpcBridgeConfig {
    fn default() -> Self {
        Self {
            quill_base_url: "http://localhost:8080".to_string(),
            enable_logging: true,
            forward_metadata: true,
        }
    }
}

/// gRPC to Quill protocol bridge
///
/// Translates gRPC requests to Quill RPC calls and responses back to gRPC format.
pub struct GrpcBridge {
    config: GrpcBridgeConfig,
    client: Arc<QuillClient>,
}

impl GrpcBridge {
    /// Create a new gRPC bridge
    pub fn new(config: GrpcBridgeConfig) -> Result<Self, String> {
        let client = QuillClient::builder()
            .base_url(&config.quill_base_url)
            .http2_only()
            .enable_compression(true)
            .build()?;

        Ok(Self {
            config,
            client: Arc::new(client),
        })
    }

    /// Bridge a unary gRPC call to Quill
    ///
    /// # Arguments
    /// * `service` - Service name (e.g., "echo.v1.EchoService")
    /// * `method` - Method name (e.g., "Echo")
    /// * `request` - gRPC request with metadata and message
    ///
    /// # Returns
    /// gRPC response with translated Quill response
    pub async fn call_unary<T, R>(
        &self,
        service: &str,
        method: &str,
        request: Request<T>,
    ) -> Result<Response<R>, Status>
    where
        T: prost::Message,
        R: prost::Message + Default,
    {
        if self.config.enable_logging {
            info!(
                service = service,
                method = method,
                "Bridging gRPC unary call to Quill"
            );
        }

        // Extract and encode the request message
        let message = request.into_inner();
        let mut request_bytes = Vec::new();
        message
            .encode(&mut request_bytes)
            .map_err(|e| Status::internal(format!("Failed to encode request: {}", e)))?;

        // Make Quill RPC call
        let response_bytes = self
            .client
            .call(service, method, Bytes::from(request_bytes))
            .await
            .map_err(|e| self.quill_error_to_grpc_status(e))?;

        // Decode response
        let response_message = R::decode(&response_bytes[..])
            .map_err(|e| Status::internal(format!("Failed to decode response: {}", e)))?;

        Ok(Response::new(response_message))
    }

    /// Convert Quill error to gRPC status
    fn quill_error_to_grpc_status(&self, error: quill_core::QuillError) -> Status {
        match error {
            quill_core::QuillError::ProblemDetails(details) => {
                let (code, message) = problem_details_to_grpc_status(&details);
                Status::new(code, message)
            }
            quill_core::QuillError::Transport(msg) => Status::unavailable(msg),
            quill_core::QuillError::Framing(msg) => Status::internal(msg),
            quill_core::QuillError::Rpc(msg) => Status::unknown(msg),
        }
    }

    /// Convert gRPC status to Quill error
    fn grpc_status_to_quill_error(&self, status: Status) -> quill_core::QuillError {
        let details = grpc_to_problem_details(status.code(), status.message().to_string());
        quill_core::QuillError::ProblemDetails(details)
    }
}

/// Helper trait for bridging gRPC services
///
/// Implement this trait for your gRPC service to enable automatic bridging to Quill.
#[tonic::async_trait]
pub trait GrpcServiceBridge {
    /// Get the service name (e.g., "echo.v1.EchoService")
    fn service_name() -> &'static str;

    /// Bridge a method call
    async fn bridge_call(
        &self,
        method: &str,
        request: Bytes,
    ) -> Result<Bytes, quill_core::QuillError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use tonic::Code;

    #[test]
    fn test_grpc_bridge_config_default() {
        let config = GrpcBridgeConfig::default();
        assert_eq!(config.quill_base_url, "http://localhost:8080");
        assert!(config.enable_logging);
        assert!(config.forward_metadata);
    }

    #[test]
    fn test_quill_error_conversion() {
        let config = GrpcBridgeConfig::default();
        let bridge = GrpcBridge::new(config).unwrap();

        let quill_error = quill_core::QuillError::Transport("Connection failed".to_string());
        let grpc_status = bridge.quill_error_to_grpc_status(quill_error);

        assert_eq!(grpc_status.code(), Code::Unavailable);
        assert_eq!(grpc_status.message(), "Connection failed");
    }

    #[test]
    fn test_grpc_status_conversion() {
        let config = GrpcBridgeConfig::default();
        let bridge = GrpcBridge::new(config).unwrap();

        let grpc_status = Status::not_found("Resource not found");
        let quill_error = bridge.grpc_status_to_quill_error(grpc_status);

        match quill_error {
            quill_core::QuillError::ProblemDetails(details) => {
                assert_eq!(details.status, 404);
                assert!(details.detail.unwrap().contains("Resource not found"));
            }
            _ => panic!("Expected ProblemDetails error"),
        }
    }
}
