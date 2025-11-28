//! Error types for REST gateway

use quill_core::ProblemDetails;
use thiserror::Error;

/// REST gateway errors
#[derive(Debug, Error)]
pub enum GatewayError {
    #[error("Route not found: {0}")]
    RouteNotFound(String),

    #[error("Method not allowed: {method} for path {path}")]
    MethodNotAllowed { method: String, path: String },

    #[error("Invalid request body: {0}")]
    InvalidRequestBody(String),

    #[error("Invalid response: {0}")]
    InvalidResponse(String),

    #[error("JSON serialization error: {0}")]
    JsonSerialization(#[from] serde_json::Error),

    #[error("Protobuf error: {0}")]
    Protobuf(String),

    #[error("RPC call failed: {0}")]
    RpcCall(String),

    #[error("RPC not found: {0}")]
    RpcNotFound(String),

    #[error("Invalid path parameter: {0}")]
    InvalidPathParam(String),

    #[error("Missing required field: {0}")]
    MissingField(String),

    #[error("Internal error: {0}")]
    InternalError(String),

    #[error("No converter configured for JSON/Protobuf conversion")]
    NoConverter,
}

/// Result type for gateway operations
pub type GatewayResult<T> = Result<T, GatewayError>;

impl GatewayError {
    /// Convert gateway error to Problem Details
    pub fn to_problem_details(&self) -> ProblemDetails {
        match self {
            GatewayError::RouteNotFound(path) => ProblemDetails {
                type_uri: "urn:quill:rest-gateway:route-not-found".to_string(),
                title: "Route Not Found".to_string(),
                status: 404,
                detail: Some(format!("No route found for path: {}", path)),
                instance: None,
                quill_proto_type: None,
                quill_proto_detail_base64: None,
            },
            GatewayError::MethodNotAllowed { method, path } => ProblemDetails {
                type_uri: "urn:quill:rest-gateway:method-not-allowed".to_string(),
                title: "Method Not Allowed".to_string(),
                status: 405,
                detail: Some(format!("{} not allowed for path: {}", method, path)),
                instance: None,
                quill_proto_type: None,
                quill_proto_detail_base64: None,
            },
            GatewayError::InvalidRequestBody(msg) => ProblemDetails {
                type_uri: "urn:quill:rest-gateway:invalid-request".to_string(),
                title: "Invalid Request Body".to_string(),
                status: 400,
                detail: Some(msg.clone()),
                instance: None,
                quill_proto_type: None,
                quill_proto_detail_base64: None,
            },
            GatewayError::InvalidPathParam(msg) => ProblemDetails {
                type_uri: "urn:quill:rest-gateway:invalid-path-param".to_string(),
                title: "Invalid Path Parameter".to_string(),
                status: 400,
                detail: Some(msg.clone()),
                instance: None,
                quill_proto_type: None,
                quill_proto_detail_base64: None,
            },
            GatewayError::MissingField(field) => ProblemDetails {
                type_uri: "urn:quill:rest-gateway:missing-field".to_string(),
                title: "Missing Required Field".to_string(),
                status: 400,
                detail: Some(format!("Required field '{}' is missing", field)),
                instance: None,
                quill_proto_type: None,
                quill_proto_detail_base64: None,
            },
            GatewayError::RpcCall(msg) => ProblemDetails {
                type_uri: "urn:quill:rest-gateway:rpc-error".to_string(),
                title: "RPC Call Failed".to_string(),
                status: 500,
                detail: Some(msg.clone()),
                instance: None,
                quill_proto_type: None,
                quill_proto_detail_base64: None,
            },
            GatewayError::RpcNotFound(msg) => ProblemDetails {
                type_uri: "urn:quill:rest-gateway:rpc-not-found".to_string(),
                title: "RPC Not Found".to_string(),
                status: 404,
                detail: Some(msg.clone()),
                instance: None,
                quill_proto_type: None,
                quill_proto_detail_base64: None,
            },
            GatewayError::InternalError(msg) => ProblemDetails {
                type_uri: "urn:quill:rest-gateway:internal-error".to_string(),
                title: "Internal Gateway Error".to_string(),
                status: 500,
                detail: Some(msg.clone()),
                instance: None,
                quill_proto_type: None,
                quill_proto_detail_base64: None,
            },
            GatewayError::NoConverter => ProblemDetails {
                type_uri: "urn:quill:rest-gateway:no-converter".to_string(),
                title: "Converter Not Configured".to_string(),
                status: 500,
                detail: Some("No message converter configured for JSON/Protobuf conversion".to_string()),
                instance: None,
                quill_proto_type: None,
                quill_proto_detail_base64: None,
            },
            _ => ProblemDetails {
                type_uri: "urn:quill:rest-gateway:internal-error".to_string(),
                title: "Internal Gateway Error".to_string(),
                status: 500,
                detail: Some(self.to_string()),
                instance: None,
                quill_proto_type: None,
                quill_proto_detail_base64: None,
            },
        }
    }

    /// Get HTTP status code for this error
    pub fn status_code(&self) -> u16 {
        self.to_problem_details().status
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_route_not_found_error() {
        let err = GatewayError::RouteNotFound("/api/v1/unknown".to_string());
        let problem = err.to_problem_details();
        assert_eq!(problem.status, 404);
        assert_eq!(problem.title, "Route Not Found");
    }

    #[test]
    fn test_method_not_allowed_error() {
        let err = GatewayError::MethodNotAllowed {
            method: "DELETE".to_string(),
            path: "/api/v1/users/123".to_string(),
        };
        let problem = err.to_problem_details();
        assert_eq!(problem.status, 405);
    }

    #[test]
    fn test_invalid_request_error() {
        let err = GatewayError::InvalidRequestBody("Invalid JSON".to_string());
        assert_eq!(err.status_code(), 400);
    }
}
