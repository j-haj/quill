//! gRPC to Quill bridge implementation

use crate::status::{grpc_to_problem_details, problem_details_to_grpc_status};
use bytes::Bytes;
use quill_client::QuillClient;
use std::sync::Arc;
use tokio_stream::wrappers::ReceiverStream;
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

    /// Bridge server streaming call (gRPC server → Quill client)
    ///
    /// Server sends multiple responses.
    pub async fn call_server_streaming<T, R>(
        &self,
        service: &str,
        method: &str,
        request: Request<T>,
    ) -> Result<Response<ReceiverStream<Result<R, Status>>>, Status>
    where
        T: prost::Message,
        R: prost::Message + Default + Send + 'static,
    {
        if self.config.enable_logging {
            info!(
                service = service,
                method = method,
                "Bridging gRPC server streaming call to Quill"
            );
        }

        // Encode request
        let message = request.into_inner();
        let mut request_bytes = Vec::new();
        message
            .encode(&mut request_bytes)
            .map_err(|e| Status::internal(format!("Failed to encode request: {}", e)))?;

        // Make Quill server streaming call
        let mut quill_stream = self
            .client
            .call_server_streaming(&service, &method, Bytes::from(request_bytes))
            .await
            .map_err(|e| self.quill_error_to_grpc_status(e))?;

        // Create channel for streaming responses
        let (tx, rx) = tokio::sync::mpsc::channel(32);

        // Spawn task to read Quill stream and convert to gRPC
        tokio::spawn(async move {
            use tokio_stream::StreamExt;

            while let Some(result) = quill_stream.next().await {
                match result {
                    Ok(response_bytes) => {
                        // Decode response
                        match R::decode(&response_bytes[..]) {
                            Ok(message) => {
                                if tx.send(Ok(message)).await.is_err() {
                                    // Receiver dropped
                                    break;
                                }
                            }
                            Err(e) => {
                                let _ = tx
                                    .send(Err(Status::internal(format!(
                                        "Failed to decode response: {}",
                                        e
                                    ))))
                                    .await;
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        // Convert Quill error to gRPC status
                        let status = match e {
                            quill_core::QuillError::ProblemDetails(details) => {
                                let (code, message) = problem_details_to_grpc_status(&details);
                                Status::new(code, message)
                            }
                            quill_core::QuillError::Transport(msg) => Status::unavailable(msg),
                            quill_core::QuillError::Framing(msg) => Status::internal(msg),
                            quill_core::QuillError::Rpc(msg) => Status::unknown(msg),
                        };
                        let _ = tx.send(Err(status)).await;
                        break;
                    }
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
    }

    /// Bridge client streaming call (gRPC client → Quill server)
    ///
    /// Client sends multiple requests.
    pub async fn call_client_streaming<T, R>(
        &self,
        service: &str,
        method: &str,
        request: Request<tonic::Streaming<T>>,
    ) -> Result<Response<R>, Status>
    where
        T: prost::Message + Send + 'static,
        R: prost::Message + Default,
    {
        if self.config.enable_logging {
            info!(
                service = service,
                method = method,
                "Bridging gRPC client streaming call to Quill"
            );
        }

        let mut grpc_stream = request.into_inner();

        // Create a Quill stream from the gRPC stream
        let quill_stream = async_stream::stream! {
            while let Some(result) = grpc_stream.message().await.transpose() {
                match result {
                    Ok(message) => {
                        // Encode message to bytes
                        let mut bytes = Vec::new();
                        if let Err(e) = message.encode(&mut bytes) {
                            yield Err(quill_core::QuillError::Rpc(format!(
                                "Failed to encode message: {}",
                                e
                            )));
                            break;
                        }
                        yield Ok(Bytes::from(bytes));
                    }
                    Err(e) => {
                        yield Err(quill_core::QuillError::Transport(format!("Stream error: {}", e)));
                        break;
                    }
                }
            }
        };

        // Make Quill client streaming call
        let response_bytes = self
            .client
            .call_client_streaming(&service, &method, Box::pin(quill_stream))
            .await
            .map_err(|e| self.quill_error_to_grpc_status(e))?;

        // Decode response
        let response_message = R::decode(&response_bytes[..])
            .map_err(|e| Status::internal(format!("Failed to decode response: {}", e)))?;

        Ok(Response::new(response_message))
    }

    /// Bridge bidirectional streaming call (both sides stream)
    pub async fn call_bidi_streaming<T, R>(
        &self,
        service: &str,
        method: &str,
        request: Request<tonic::Streaming<T>>,
    ) -> Result<Response<ReceiverStream<Result<R, Status>>>, Status>
    where
        T: prost::Message + Send + 'static,
        R: prost::Message + Default + Send + 'static,
    {
        if self.config.enable_logging {
            info!(
                service = service,
                method = method,
                "Bridging gRPC bidirectional streaming call to Quill"
            );
        }

        let mut grpc_stream = request.into_inner();

        // Create a Quill stream from the gRPC stream
        let quill_stream = async_stream::stream! {
            while let Some(result) = grpc_stream.message().await.transpose() {
                match result {
                    Ok(message) => {
                        // Encode message to bytes
                        let mut bytes = Vec::new();
                        if let Err(e) = message.encode(&mut bytes) {
                            yield Err(quill_core::QuillError::Rpc(format!(
                                "Failed to encode message: {}",
                                e
                            )));
                            break;
                        }
                        yield Ok(Bytes::from(bytes));
                    }
                    Err(e) => {
                        yield Err(quill_core::QuillError::Transport(format!("Stream error: {}", e)));
                        break;
                    }
                }
            }
        };

        // Make Quill bidirectional streaming call
        let mut quill_response_stream = self
            .client
            .call_bidi_streaming(&service, &method, Box::pin(quill_stream))
            .await
            .map_err(|e| self.quill_error_to_grpc_status(e))?;

        // Create channel for streaming responses
        let (tx, rx) = tokio::sync::mpsc::channel(32);

        // Spawn task to read Quill stream and convert to gRPC
        tokio::spawn(async move {
            use tokio_stream::StreamExt;

            while let Some(result) = quill_response_stream.next().await {
                match result {
                    Ok(response_bytes) => {
                        // Decode response
                        match R::decode(&response_bytes[..]) {
                            Ok(message) => {
                                if tx.send(Ok(message)).await.is_err() {
                                    // Receiver dropped
                                    break;
                                }
                            }
                            Err(e) => {
                                let _ = tx
                                    .send(Err(Status::internal(format!(
                                        "Failed to decode response: {}",
                                        e
                                    ))))
                                    .await;
                                break;
                            }
                        }
                    }
                    Err(e) => {
                        // Convert Quill error to gRPC status
                        let status = match e {
                            quill_core::QuillError::ProblemDetails(details) => {
                                let (code, message) = problem_details_to_grpc_status(&details);
                                Status::new(code, message)
                            }
                            quill_core::QuillError::Transport(msg) => Status::unavailable(msg),
                            quill_core::QuillError::Framing(msg) => Status::internal(msg),
                            quill_core::QuillError::Rpc(msg) => Status::unknown(msg),
                        };
                        let _ = tx.send(Err(status)).await;
                        break;
                    }
                }
            }
        });

        Ok(Response::new(ReceiverStream::new(rx)))
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

    // Note: Comprehensive integration tests for streaming require a running Quill server
    // and gRPC client setup. These tests document the behavior and validate the types.

    #[test]
    fn test_bridge_creation() {
        let config = GrpcBridgeConfig {
            quill_base_url: "http://localhost:8080".to_string(),
            enable_logging: true,
            forward_metadata: true,
        };

        let bridge = GrpcBridge::new(config);
        assert!(bridge.is_ok(), "Bridge should be created successfully");
    }

    #[test]
    fn test_bridge_with_custom_url() {
        let config = GrpcBridgeConfig {
            quill_base_url: "http://custom-server:9090".to_string(),
            enable_logging: false,
            forward_metadata: false,
        };

        let bridge = GrpcBridge::new(config);
        assert!(bridge.is_ok(), "Bridge should work with custom configuration");
    }

    #[test]
    fn test_all_quill_error_types_convert_to_grpc() {
        let config = GrpcBridgeConfig::default();
        let bridge = GrpcBridge::new(config).unwrap();

        // Test Transport error
        let transport_err = quill_core::QuillError::Transport("Network error".to_string());
        let status = bridge.quill_error_to_grpc_status(transport_err);
        assert_eq!(status.code(), Code::Unavailable);

        // Test Framing error
        let framing_err = quill_core::QuillError::Framing("Invalid frame".to_string());
        let status = bridge.quill_error_to_grpc_status(framing_err);
        assert_eq!(status.code(), Code::Internal);

        // Test Rpc error
        let rpc_err = quill_core::QuillError::Rpc("RPC failed".to_string());
        let status = bridge.quill_error_to_grpc_status(rpc_err);
        assert_eq!(status.code(), Code::Unknown);
    }

    #[test]
    fn test_problem_details_error_conversion() {
        let config = GrpcBridgeConfig::default();
        let bridge = GrpcBridge::new(config).unwrap();

        let problem = quill_core::ProblemDetails {
            type_uri: "urn:test:error".to_string(),
            title: "Test Error".to_string(),
            status: 400,
            detail: Some("Bad request details".to_string()),
            instance: None,
            quill_proto_type: None,
            quill_proto_detail_base64: None,
        };

        let quill_err = quill_core::QuillError::ProblemDetails(problem);
        let status = bridge.quill_error_to_grpc_status(quill_err);

        assert_eq!(status.code(), Code::InvalidArgument);
        assert!(status.message().contains("Bad request details"));
    }

    #[test]
    fn test_config_logging_flag() {
        let config = GrpcBridgeConfig {
            quill_base_url: "http://localhost:8080".to_string(),
            enable_logging: false,
            forward_metadata: true,
        };

        assert!(!config.enable_logging);
        assert!(config.forward_metadata);
    }
}
