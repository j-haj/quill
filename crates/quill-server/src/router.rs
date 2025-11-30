//! HTTP router for RPC methods
//!
//! Routes match the pattern: /{package}.{Service}/{Method}

use bytes::Bytes;
use futures_util::stream::StreamExt as FuturesStreamExt;
use http::{Method, Request, Response, StatusCode};
use http_body_util::{combinators::UnsyncBoxBody, BodyExt, Full, StreamBody};
use hyper::body::{Frame as HyperFrame, Incoming};
use quill_core::{Frame, ProblemDetails, QuillError};
use crate::request_stream::RequestFrameStream;
use crate::streaming::RpcResponse;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use tokio_stream::Stream;

/// Type alias for request stream (for client streaming)
pub type RequestStream = Pin<Box<dyn Stream<Item = Result<Bytes, QuillError>> + Send>>;

/// Type alias for async handler functions (returns RpcResponse for streaming support)
pub type HandlerFn =
    Arc<dyn Fn(Bytes) -> Pin<Box<dyn Future<Output = Result<RpcResponse, QuillError>> + Send>> + Send + Sync>;

/// Type alias for client streaming handlers (takes request stream, returns unary response)
pub type ClientStreamingHandlerFn =
    Arc<dyn Fn(RequestStream) -> Pin<Box<dyn Future<Output = Result<RpcResponse, QuillError>> + Send>> + Send + Sync>;

/// Type alias for bidirectional streaming handlers (takes request stream, returns response stream)
pub type BidiStreamingHandlerFn =
    Arc<dyn Fn(RequestStream) -> Pin<Box<dyn Future<Output = Result<RpcResponse, QuillError>> + Send>> + Send + Sync>;

/// Handler type enum for different streaming modes
enum Handler {
    /// Unary or server-streaming (request is collected upfront)
    Unary(HandlerFn),
    /// Client streaming (request is a stream)
    ClientStreaming(ClientStreamingHandlerFn),
    /// Bidirectional streaming (request is a stream, response is a stream)
    Bidi(BidiStreamingHandlerFn),
}

/// RPC Router
pub struct RpcRouter {
    routes: HashMap<String, Handler>,
}

impl RpcRouter {
    /// Create a new router
    pub fn new() -> Self {
        Self {
            routes: HashMap::new(),
        }
    }

    /// Register a handler for a specific service method
    /// Path format: "{package}.{Service}/{Method}"
    pub fn register<F, Fut>(&mut self, path: impl Into<String>, handler: F)
    where
        F: Fn(Bytes) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<RpcResponse, QuillError>> + Send + 'static,
    {
        let handler = Arc::new(move |req: Bytes| Box::pin(handler(req)) as Pin<Box<_>>);
        self.routes.insert(path.into(), Handler::Unary(handler));
    }

    /// Register a unary handler (convenience method that wraps response in RpcResponse::Unary)
    pub fn register_unary<F, Fut>(&mut self, path: impl Into<String>, handler: F)
    where
        F: Fn(Bytes) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<Bytes, QuillError>> + Send + 'static,
    {
        let handler = Arc::new(handler);
        self.register(path, move |req: Bytes| {
            let handler = Arc::clone(&handler);
            async move {
                let result = handler(req).await?;
                Ok(RpcResponse::Unary(result))
            }
        });
    }

    /// Register a client streaming handler
    ///
    /// The handler receives a stream of request messages and returns a single response.
    pub fn register_client_streaming<F, Fut>(&mut self, path: impl Into<String>, handler: F)
    where
        F: Fn(RequestStream) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<RpcResponse, QuillError>> + Send + 'static,
    {
        let handler: ClientStreamingHandlerFn = Arc::new(move |stream: RequestStream| {
            Box::pin(handler(stream)) as Pin<Box<_>>
        });
        self.routes.insert(path.into(), Handler::ClientStreaming(handler));
    }

    /// Register a bidirectional streaming handler
    ///
    /// The handler receives a stream of request messages and returns a stream of responses.
    pub fn register_bidi_streaming<F, Fut>(&mut self, path: impl Into<String>, handler: F)
    where
        F: Fn(RequestStream) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<RpcResponse, QuillError>> + Send + 'static,
    {
        let handler: BidiStreamingHandlerFn = Arc::new(move |stream: RequestStream| {
            Box::pin(handler(stream)) as Pin<Box<_>>
        });
        self.routes.insert(path.into(), Handler::Bidi(handler));
    }

    /// Route an incoming request
    pub async fn route(&self, req: Request<Incoming>) -> Response<UnsyncBoxBody<Bytes, QuillError>> {
        // Parse the path
        let path = req.uri().path();

        // Validate HTTP method (should be POST for RPC)
        if req.method() != Method::POST {
            return Self::error_response(
                StatusCode::METHOD_NOT_ALLOWED,
                "Method not allowed",
                Some("Only POST is supported for RPC calls"),
            );
        }

        // Strip leading slash
        let path = path.strip_prefix('/').unwrap_or(path);

        // Find handler
        let handler = match self.routes.get(path) {
            Some(h) => h,
            None => {
                return Self::error_response(
                    StatusCode::NOT_FOUND,
                    "Method not found",
                    Some(&format!("No handler registered for path: /{}", path)),
                )
            }
        };

        // Dispatch based on handler type
        let result = match handler {
            Handler::Unary(handler) => {
                // Read entire request body for unary/server-streaming
                match Self::read_body(req.into_body()).await {
                    Ok(body) => handler(body).await,
                    Err(e) => {
                        return Self::error_response(
                            StatusCode::BAD_REQUEST,
                            "Failed to read request body",
                            Some(&e.to_string()),
                        );
                    }
                }
            }
            Handler::ClientStreaming(handler) | Handler::Bidi(handler) => {
                // Create request stream for client/bidi streaming
                let request_stream = RequestFrameStream::new(req.into_body());
                let boxed_stream: RequestStream = Box::pin(request_stream);
                handler(boxed_stream).await
            }
        };

        // Handle result
        match result {
            Ok(RpcResponse::Unary(response_bytes)) => {
                // Unary response
                Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/proto")
                    .body(Full::new(response_bytes).map_err(|never| match never {}).boxed_unsync())
                    .unwrap()
            }
            Ok(RpcResponse::Streaming(stream)) => {
                // Streaming response - encode each message as a frame
                let frame_stream = stream.map(|result| match result {
                    Ok(data) => {
                        let frame = Frame::data(data);
                        Ok(HyperFrame::data(frame.encode()))
                    }
                    Err(e) => Err(e),
                });

                // Create the end frame stream
                let with_end = frame_stream.chain(futures_util::stream::once(async {
                    let end_frame = Frame::end_stream();
                    Ok(HyperFrame::data(end_frame.encode()))
                }));

                Response::builder()
                    .status(StatusCode::OK)
                    .header("Content-Type", "application/proto")
                    .header("Transfer-Encoding", "chunked")
                    .body(StreamBody::new(with_end).boxed_unsync())
                    .unwrap()
            }
            Err(QuillError::ProblemDetails(pd)) => {
                // Return Problem Details as JSON
                let json = pd.to_json().unwrap_or_else(|_| "{}".to_string());
                Response::builder()
                    .status(StatusCode::from_u16(pd.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR))
                    .header("Content-Type", "application/problem+json")
                    .body(Full::new(Bytes::from(json)).map_err(|never| match never {}).boxed_unsync())
                    .unwrap()
            }
            Err(e) => Self::error_response(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Internal server error",
                Some(&e.to_string()),
            ),
        }
    }

    /// Helper to read body bytes
    async fn read_body(body: Incoming) -> Result<Bytes, Box<dyn std::error::Error + Send + Sync>> {
        use http_body_util::BodyExt;
        let collected = body.collect().await?;
        Ok(collected.to_bytes())
    }

    /// Helper to create error responses
    fn error_response(status: StatusCode, title: &str, detail: Option<&str>) -> Response<UnsyncBoxBody<Bytes, QuillError>> {
        let mut pd = ProblemDetails::new(status, title);
        if let Some(d) = detail {
            pd = pd.with_detail(d);
        }

        let json = pd.to_json().unwrap_or_else(|_| "{}".to_string());

        Response::builder()
            .status(status)
            .header("Content-Type", "application/problem+json")
            .body(Full::new(Bytes::from(json)).map_err(|never| match never {}).boxed_unsync())
            .unwrap()
    }
}

impl Default for RpcRouter {
    fn default() -> Self {
        Self::new()
    }
}

/// Parse a Quill RPC path into (service, method)
/// Expected format: "{package}.{Service}/{Method}"
pub fn parse_rpc_path(path: &str) -> Option<(String, String)> {
    // Strip leading slash
    let path = path.strip_prefix('/').unwrap_or(path);

    // Split on '/'
    let parts: Vec<&str> = path.split('/').collect();
    if parts.len() != 2 {
        return None;
    }

    let service = parts[0].to_string();
    let method = parts[1].to_string();

    Some((service, method))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_rpc_path() {
        let (service, method) = parse_rpc_path("/echo.v1.EchoService/Echo").unwrap();
        assert_eq!(service, "echo.v1.EchoService");
        assert_eq!(method, "Echo");

        let (service, method) = parse_rpc_path("media.v1.ImageService/GetMetadata").unwrap();
        assert_eq!(service, "media.v1.ImageService");
        assert_eq!(method, "GetMetadata");

        assert!(parse_rpc_path("/invalid").is_none());
    }
}
